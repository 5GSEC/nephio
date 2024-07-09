/*
Copyright 2023 The Nephio Authors.

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

package bootstrapsecret

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/nephio-project/nephio/controllers/pkg/cluster"
	reconcilerinterface "github.com/nephio-project/nephio/controllers/pkg/reconcilers/reconciler-interface"
	"github.com/nephio-project/nephio/controllers/pkg/resource"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	vault "github.com/hashicorp/vault/api"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	capiv1beta1 "sigs.k8s.io/cluster-api/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func init() {
	reconcilerinterface.Register("workloadidentity", &reconciler{})
}

type LoginPayload struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

type AuthResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
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

// r.List --> gets us cluster name list

func (r *reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetch the Cluster instance

	// List all Cluster instances
	// clusterList := &capiv1beta1.ClusterList{}
	// err := r.List(ctx, clusterList)
	// if err != nil {
	// 	log.Error(err, "unable to list Clusters")
	// 	return reconcile.Result{}, err
	// }

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
	configMap := &corev1.ConfigMap{}
	err = r.Get(ctx, configMapName, configMap)
	if err != nil {
		log.Error(err, "unable to fetch ConfigMap")
		return reconcile.Result{}, err
	}

	secrets := &corev1.SecretList{}
	if err := r.List(ctx, secrets); err != nil {
		msg := "cannot list secrets"
		log.Error(err, msg)
		return ctrl.Result{}, errors.Wrap(err, msg)
	}

	vaultAddr := "http://10.146.0.21:8200"

	jwtSVID, err := getJWT(ctx)
	if err != nil {
		log.Error(err, "Unable to get jwtSVID")
	}

	clientToken, err := authenticateToVault(vaultAddr, jwtSVID.Marshal(), "dev")
	if err != nil {
		log.Error(err, "Error authenticating to Vault:")
	}

	fmt.Printf("Successfully authenticated to Vault. Client token: %s\n", clientToken)

	config := vault.DefaultConfig()
	config.Address = vaultAddr
	client, err := vault.NewClient(config)
	if err != nil {
		log.Error(err, "Unable to create Vault client:")
	}

	client.SetToken(clientToken)

	for _, secret := range secrets.Items {
		if strings.Contains(secret.GetName(), cl.Name) {
			secret := secret
			storeKubeconfig(secret, client, "secret/my-super-secret", cl.Name)
			// clusterClient, ok := cluster.Cluster{Client: r.Client}.GetClusterClient(&secret)
		}
	}

	// secret, err := getSecret(client, "secret/my-super-secret")

	kubeconfig, err := fetchKubeconfig(client, "secret/my-super-secret", cl.Name)
	if err != nil {
		log.Error(err, "Error retrieving secret:")
	}

	decodedKubeConfig, err := base64.StdEncoding.DecodeString(kubeconfig)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
	}

	fmt.Printf("Secret retrieved: %v\n", decodedKubeConfig)

	Client, err := createK8sClientFromKubeconfig(decodedKubeConfig)

	createK8sResources(Client)
	if err != nil {
		fmt.Println("Error creating K8s", err)
	}

	found := false
	for _, secret := range secrets.Items {
		if strings.Contains(secret.GetName(), cl.Name) {
			secret := secret // required to prevent gosec warning: G601 (CWE-118): Implicit memory aliasing in for loop
			clusterClient, ok := cluster.Cluster{Client: r.Client}.GetClusterClient(&secret)
			if ok {
				found = true
				clusterClient, ready, err := clusterClient.GetClusterClient(ctx)
				if err != nil {
					msg := "cannot get clusterClient"
					log.Error(err, msg)
					return ctrl.Result{RequeueAfter: 30 * time.Second}, errors.Wrap(err, msg)
				}
				if !ready {
					log.Info("cluster not ready")
					return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
				}

				remoteNamespace := configMap.Namespace
				// if rns, ok := configMap.GetAnnotations()[remoteNamespaceKey]; ok {
				// 	remoteNamespace = rns
				// }
				// check if the remote namespace exists, if not retry
				ns := &corev1.Namespace{}
				if err = clusterClient.Get(ctx, types.NamespacedName{Name: remoteNamespace}, ns); err != nil {
					if resource.IgnoreNotFound(err) != nil {
						msg := fmt.Sprintf("cannot get namespace: %s", remoteNamespace)
						log.Error(err, msg)
						return ctrl.Result{RequeueAfter: 30 * time.Second}, errors.Wrap(err, msg)
					}
					msg := fmt.Sprintf("namespace: %s, does not exist, retry...", remoteNamespace)
					log.Info(msg)
					return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
				}

				newcr := configMap.DeepCopy()

				newcr.ResourceVersion = ""
				newcr.UID = ""
				newcr.Namespace = remoteNamespace
				log.Info("secret info", "secret", newcr.Annotations)
				if err := clusterClient.Apply(ctx, newcr); err != nil {
					msg := fmt.Sprintf("cannot apply secret to cluster %s", cl.Name)
					log.Error(err, msg)
					return ctrl.Result{}, errors.Wrap(err, msg)
				}
			}
		}
		if found {
			// speeds up the loop
			break
		}
	}

	return reconcile.Result{}, nil
}

func createK8sClientFromKubeconfig(kubeconfigData []byte) (*kubernetes.Clientset, error) {
	// Load the kubeconfig from the decoded data
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfigData)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %v", err)
	}

	// Create the Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes clientset: %v", err)
	}

	return clientset, nil
}

func getJWT(ctx context.Context) (*jwtsvid.SVID, error) {
	socketPath := "unix:///spiffe-workload-api/agent.sock"
	log := log.FromContext(ctx)
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		log.Info("Unable to create JWTSource: %v", err)
	}
	defer jwtSource.Close()

	audience := "TESTING"
	spiffeID := spiffeid.RequireFromString("spiffe://example.org/nephio")

	jwtSVID, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
		Subject:  spiffeID,
	})
	if err != nil {
		log.Info("Unable to fetch JWT-SVID: %v", err)
	}

	fmt.Printf("Fetched JWT-SVID: %v\n", jwtSVID.Marshal())
	if err != nil {
		log.Error(err, "Spire auth didnt work")
	}

	return jwtSVID, err
}

func authenticateToVault(vaultAddr, jwt, role string) (string, error) {
	// Create a Vault client
	config := vault.DefaultConfig()
	config.Address = vaultAddr
	client, err := vault.NewClient(config)
	if err != nil {
		return "", fmt.Errorf("unable to create Vault client: %w", err)
	}

	payload := LoginPayload{
		Role: role,
		JWT:  jwt,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("unable to marshal payload: %w", err)
	}

	// Perform the login request
	req := client.NewRequest("POST", "/v1/auth/jwt/login")
	req.Body = bytes.NewBuffer(payloadBytes)

	resp, err := client.RawRequest(req)
	if err != nil {
		return "", fmt.Errorf("unable to perform login request: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read response body: %w", err)
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", fmt.Errorf("unable to decode response: %w", err)
	}

	return authResp.Auth.ClientToken, nil
}

func storeKubeconfig(kubeconfigData corev1.Secret, client *vault.Client, secretPath, clusterName string) error {
	// Read the Kubeconfig file

	// Prepare the data to store
	data := map[string]interface{}{
		"data": map[string]interface{}{
			clusterName: kubeconfigData.Data,
		},
	}

	// Store the data in Vault
	_, err := client.Logical().Write(secretPath, data)
	if err != nil {
		return fmt.Errorf("unable to write secret to Vault: %w", err)
	}

	return nil
}

func fetchKubeconfig(client *vault.Client, secretPath, clusterName string) (string, error) {
	// Read the secret
	secret, err := client.Logical().Read(secretPath)
	if err != nil {
		return "", fmt.Errorf("unable to read secret: %w", err)
	}

	if secret == nil {
		return "", fmt.Errorf("secret not found at path: %s", secretPath)
	}

	// Extract the Kubeconfig data
	kubeconfig, ok := secret.Data["test"].(string)
	if !ok {
		return "", fmt.Errorf("kubeconfig for cluster %s not found", clusterName)
	}

	return kubeconfig, nil
}

func createK8sResources(clientset *kubernetes.Clientset) error {
	// Create ServiceAccount
	sa := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "spire-kubeconfig",
			Namespace: "spire",
		},
	}
	_, err := clientset.CoreV1().ServiceAccounts("spire").Create(context.TODO(), sa, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ServiceAccount: %v", err)
	}

	// Create ClusterRole
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod-reader",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes"},
				Verbs:     []string{"get"},
			},
		},
	}
	_, err = clientset.RbacV1().ClusterRoles().Create(context.TODO(), cr, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ClusterRole: %v", err)
	}

	// Create ClusterRoleBinding for system:auth-delegator
	crbAuthDelegator := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "spire-agent-tokenreview-binding",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "spire-kubeconfig",
				Namespace: "spire",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:auth-delegator",
		},
	}
	_, err = clientset.RbacV1().ClusterRoleBindings().Create(context.TODO(), crbAuthDelegator, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ClusterRoleBinding (auth-delegator): %v", err)
	}

	// Create ClusterRoleBinding for pod-reader
	crbPodReader := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "spire-agent-pod-reader-binding",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "spire-kubeconfig",
				Namespace: "spire",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "pod-reader",
		},
	}
	_, err = clientset.RbacV1().ClusterRoleBindings().Create(context.TODO(), crbPodReader, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ClusterRoleBinding (pod-reader): %v", err)
	}

	// Create Secret
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "agent-sa-secret",
			Namespace: "spire",
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": "spire-kubeconfig",
			},
		},
		Type: v1.SecretTypeServiceAccountToken,
	}
	_, err = clientset.CoreV1().Secrets("spire").Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Secret: %v", err)
	}

	return nil
}
