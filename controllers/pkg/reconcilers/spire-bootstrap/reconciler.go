/*
Copyright 2025 The Nephio Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package spirebootstrap

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/nephio-project/nephio/controllers/pkg/cluster"
	reconcilerinterface "github.com/nephio-project/nephio/controllers/pkg/reconcilers/reconciler-interface"
	"github.com/nephio-project/nephio/controllers/pkg/resource"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	capiv1beta1 "sigs.k8s.io/cluster-api/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const spirekubeconfig = "spire-kubeconfig"

func init() {
	reconcilerinterface.Register("workloadidentity", &reconciler{})
}

//+kubebuilder:rbac:groups=cluster.x-k8s.io,resources=clusters,verbs=get;list;watch
//+kubebuilder:rbac:groups=cluster.x-k8s.io,resources=clusters/status,verbs=get

// SetupWithManager sets up the controller with the Manager.
func (r *reconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, c any) (map[schema.GroupVersionKind]chan event.GenericEvent, error) {
	r.Client = mgr.GetClient()

	return nil, ctrl.NewControllerManagedBy(mgr).
		Named("BootstrapSpireController").
		For(&capiv1beta1.Cluster{}).
		Complete(r)
}

type reconciler struct {
	client.Client
}

func (r *reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	cl := &capiv1beta1.Cluster{}
	err := r.Get(ctx, req.NamespacedName, cl)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "unable to fetch Cluster")
		}
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	// Add your reconciliation logic here
	log.Info("Reconciling Cluster", "cluster", cl.Name)

	// Fetch the ConfigMap from the current cluster
	configMapName := types.NamespacedName{Name: "spire-bundle", Namespace: "spire"}
	configMap := &v1.ConfigMap{}
	err = r.Get(ctx, configMapName, configMap)
	if err != nil {
		log.Error(err, "unable to fetch ConfigMap")
		return reconcile.Result{}, err
	}

	secrets := &v1.SecretList{}
	if err := r.List(ctx, secrets); err != nil {
		msg := "cannot list secrets"
		log.Error(err, msg)
		return ctrl.Result{}, errors.Wrap(err, msg)
	}

	// Get the spire-server service
	spireService := &v1.Service{}
	err = r.Get(ctx, types.NamespacedName{Name: "spire-server", Namespace: "spire"}, spireService)
	if err != nil {
		msg := "failed to get spire-server service"
		log.Error(err, msg)
		return ctrl.Result{}, errors.Wrap(err, msg)
	}

	// Get the ClusterIP
	clusterIP, err := getServiceExternalIP(spireService)
	if err != nil {
		msg := "Can't get spire-server IP address"
		log.Error(err, msg)
		return ctrl.Result{}, errors.Wrap(err, msg)
	}

	// Get the port
	var port string
	if len(spireService.Spec.Ports) > 0 {
		port = fmt.Sprint(spireService.Spec.Ports[0].Port)
	}

	// Construct the service address
	spireAgentCM, err := createSpireAgentConfigMap("spire-agent", "spire", cl.Name, clusterIP, port)
	if err != nil {
		msg := "failed to create spireAgent ConfigMap"
		log.Error(err, msg)
		return ctrl.Result{}, errors.Wrap(err, msg)
	}

	for _, secret := range secrets.Items {
		if strings.Contains(secret.GetName(), cl.Name) {
			secret := secret // required to prevent gosec warning: G601 (CWE-118): Implicit memory aliasing in for loop
			clusterClient, ok := cluster.Cluster{Client: r.Client}.GetClusterClient(&secret)
			if ok {
				client, ready, err := clusterClient.GetClusterClient(ctx)
				if err != nil {
					msg := "cannot get clusterClient"
					log.Error(err, msg)
					return ctrl.Result{RequeueAfter: 30 * time.Second}, errors.Wrap(err, msg)
				}
				if !ready {
					log.Info("cluster not ready")
					return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
				}
				kubeconfig := secret.Data["value"]
				config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
				if err != nil {
					log.Error(err, "failed to get kubeconfig")
				}
				clientset, err := kubernetes.NewForConfig(config)
				if err != nil {
					log.Error(err, "failed to create rest config")
				}

				kubeconfigCM, err := r.createKubeconfigConfigMap(ctx, clientset, cl.Name)
				if err != nil {
					log.Error(err, "Error creating K8s kubeconfig configmap")
				}

				err = r.Update(ctx, kubeconfigCM)
				if err != nil {
					log.Error(err, "failed to create rest config")
				}

				err = r.updateClusterListConfigMap(ctx, cl.Name)
				if err != nil {
					log.Error(err, "Cluster list could not be updated...: ")
				}

				remoteNamespace := configMap.Namespace
				ns := &v1.Namespace{}
				if err = client.Get(ctx, types.NamespacedName{Name: remoteNamespace}, ns); err != nil {
					if resource.IgnoreNotFound(err) != nil {
						msg := fmt.Sprintf("cannot get namespace: %s", remoteNamespace)
						log.Error(err, msg)
						return ctrl.Result{RequeueAfter: 30 * time.Second}, errors.Wrap(err, msg)
					}
					msg := fmt.Sprintf("namespace: %s, does not exist, retry...", remoteNamespace)
					log.Error(err, msg)
					return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
				}

				newcr := configMap.DeepCopy()

				newcr.ResourceVersion = ""
				newcr.UID = ""
				newcr.Namespace = remoteNamespace

				newAgentConf := spireAgentCM.DeepCopy()
				newAgentConf.ResourceVersion = ""
				newAgentConf.UID = ""
				newAgentConf.Namespace = remoteNamespace
				log.Info("secret info", "secret", newcr.Annotations)
				log.Info("configMap info", "configMap", newAgentConf.Annotations)
				if err := client.Apply(ctx, newcr); err != nil {
					msg := fmt.Sprintf("cannot apply spire-bundle configMap to cluster %s", cl.Name)
					log.Error(err, msg)
					return ctrl.Result{}, errors.Wrap(err, msg)
				}
				if err := client.Apply(ctx, newAgentConf); err != nil {
					msg := fmt.Sprintf("cannot apply spire-agent configMap to cluster %s", cl.Name)
					log.Error(err, msg)
					return ctrl.Result{}, errors.Wrap(err, msg)
				}
			}
		}

	}

	return reconcile.Result{}, nil
}

func (r *reconciler) createKubeconfigConfigMap(ctx context.Context, clientset *kubernetes.Clientset, clustername string) (*v1.ConfigMap, error) {
	log := log.FromContext(ctx)

	log.Info("Creating Kubeconfig ConfigMap for the cluster", "clusterName", clustername)

	cmName := types.NamespacedName{Name: "kubeconfigs", Namespace: "spire"}
	restrictedKC := &v1.ConfigMap{}
	err := r.Get(ctx, cmName, restrictedKC)
	if err != nil {
		msg := "failed to get existing ConfigMap"
		log.Error(err, msg)
		return nil, errors.Wrap(err, msg)
	}

	// Retrieve the ServiceAccount token
	secret, err := clientset.CoreV1().Secrets("spire").Get(ctx, "agent-sa-secret", metav1.GetOptions{})
	if err != nil {
		msg := "failed to get Service Account token"
		log.Error(err, msg)
		return nil, errors.Wrap(err, msg)
	}
	token := string(secret.Data["token"])

	// Retrieve the cluster's CA certificate
	configMap, err := clientset.CoreV1().ConfigMaps("kube-system").Get(ctx, "kube-root-ca.crt", metav1.GetOptions{})
	if err != nil {
		msg := "failed to get cluster CA"
		log.Error(err, msg)
		return nil, errors.Wrap(err, msg)
	}
	caCert := configMap.Data["ca.crt"]
	caCertEncoded := strings.TrimSpace(base64.StdEncoding.EncodeToString([]byte(caCert)))

	config := KubernetesConfig{
		APIVersion: "v1",
		Kind:       "Config",
		Clusters: []Cluster{
			{
				Name: clustername,
				Cluster: ClusterDetail{
					CertificateAuthorityData: caCertEncoded,
					Server:                   clientset.RESTClient().Get().URL().String(),
				},
			},
		},
		Contexts: []Context{
			{
				Name: "spire-kubeconfig@" + clustername,
				Context: ContextDetails{
					Cluster:   clustername,
					Namespace: "spire",
					User:      spirekubeconfig,
				},
			},
		},
		Users: []User{
			{
				Name: spirekubeconfig,
				User: UserDetail{
					Token: token,
				},
			},
		},
		CurrentContext: "spire-kubeconfig@" + clustername,
	}

	// Convert to YAML
	yamlData, err := yaml.Marshal(&config)
	if err != nil {
		msg := "failed to create kubeconfig CM"
		log.Error(err, msg)
		return nil, errors.Wrap(err, msg)
	}

	// Generate a unique key for the new kubeconfig
	newConfigKey := fmt.Sprintf("kubeconfig-%s", clustername)

	// Add the new kubeconfig to the existing ConfigMap
	if restrictedKC.Data == nil {
		restrictedKC.Data = make(map[string]string)
	}
	restrictedKC.Data[newConfigKey] = string(yamlData)

	log.Info("Kubeconfig added to the ConfigMap successfully", "clusterName", clustername)

	return restrictedKC, nil
}

func (r *reconciler) updateClusterListConfigMap(ctx context.Context, clusterName string) error {
	log := log.FromContext(ctx)
	log.Info("Updating Cluster List...", "ClusterName", clusterName)

	// Get the ConfigMap
	cm := &v1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: "spire",
		Name:      "clusters",
	}, cm); err != nil {
		msg := "failed to get clusters ConfigMap"
		log.Error(err, msg)
		return errors.Wrap(err, msg)
	}

	// Get the clusters.conf data
	clustersConf, exists := cm.Data["clusters.conf"]
	if !exists {
		// Initialize empty configuration if not exists
		clustersConf = "clusters = {}"
	}

	// Remove any initial pipe character and whitespace
	clustersConf = strings.TrimPrefix(clustersConf, "|")
	clustersConf = strings.TrimSpace(clustersConf)

	// Parse existing HCL
	file, diags := hclwrite.ParseConfig([]byte(clustersConf), "clusters.conf", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return fmt.Errorf("failed to parse HCL: %s", diags.Error())
	}

	// Get or create clusters block
	rootBody := file.Body()
	var clustersBlock *hclwrite.Block

	// Look for existing clusters block
	for _, block := range rootBody.Blocks() {
		if block.Type() == "clusters" {
			clustersBlock = block
			break
		}
	}

	// Create new clusters block if it doesn't exist
	if clustersBlock == nil {
		clustersBlock = rootBody.AppendNewBlock("clusters", nil)
	}

	// Check if cluster already exists
	clusterExists := false
	clustersBody := clustersBlock.Body()
	for _, block := range clustersBody.Blocks() {
		if block.Type() == clusterName {
			clusterExists = true
			break
		}
	}

	if !clusterExists {
		// Add new cluster
		clusterBlock := clustersBody.AppendNewBlock(clusterName, nil)
		clusterBody := clusterBlock.Body()

		// Set cluster attributes
		clusterBody.SetAttributeValue("service_account_allow_list",
			cty.ListVal([]cty.Value{cty.StringVal("spire:spire-agent")}))
		clusterBody.SetAttributeValue("kube_config_file",
			cty.StringVal(fmt.Sprintf("/run/spire/kubeconfigs/kubeconfig-%s", clusterName)))
	}

	// Format the configuration
	newConfig := string(file.Bytes())
	formattedConf := "|\n    " + strings.Replace(newConfig, "\n", "\n    ", -1)

	// Update the ConfigMap
	cm.Data = map[string]string{
		"clusters.conf": formattedConf,
	}

	if err := r.Update(ctx, cm); err != nil {
		msg := "error updating Cluster List ConfigMap"
		log.Error(err, msg)
		return errors.Wrap(err, msg)
	}

	log.Info("Cluster added to the Cluster List", "clusterName", clusterName)
	return nil
}
