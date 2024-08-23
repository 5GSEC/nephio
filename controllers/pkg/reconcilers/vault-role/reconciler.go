package vaultcontroller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	vaultClient "github.com/nephio-project/nephio/controllers/pkg/vault-client"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultapi "github.com/hashicorp/vault/api"
)

// VaultJWTRoleReconciler reconciles a VaultJWTRole object
type VaultJWTRoleReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	Vault  *vaultapi.Client
}

func (r *VaultJWTRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("VaultController").
		For(&vaultClient.VaultJWTRole{}).
		Complete(r)
}

// +kubebuilder:rbac:groups=vault.example.com,resources=vaultjwtroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.example.com,resources=vaultjwtroles/status,verbs=get;update;patch

func (r *VaultJWTRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	fmt.Println("WOOH TEST")
	log := r.Log.WithValues("vaultjwtrole", req.NamespacedName)

	var vaultJWTRole vaultClient.VaultJWTRole
	if err := r.Get(ctx, req.NamespacedName, &vaultJWTRole); err != nil {
		log.Error(err, "unable to fetch VaultJWTRole")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	rolePath := fmt.Sprintf("auth/jwt/role/%s", vaultJWTRole.Name)
	_, err := r.Vault.Logical().Write(rolePath, map[string]interface{}{
		"role_type":       vaultJWTRole.Spec.RoleType,
		"user_claim":      vaultJWTRole.Spec.UserClaim,
		"bound_audiences": vaultJWTRole.Spec.BoundAudiences,
		"bound_subject":   vaultJWTRole.Spec.BoundSubject,
		"token_ttl":       vaultJWTRole.Spec.TokenTtl,
		"token_policies":  vaultJWTRole.Spec.TokenPolicies,
	})
	if err != nil {
		log.Error(err, "failed to create/update Vault JWT role")
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}

	log.Info("Successfully reconciled VaultJWTRole")
	return ctrl.Result{}, nil
}
