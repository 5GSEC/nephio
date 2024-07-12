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

package vaultClient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	vault "github.com/hashicorp/vault/api"

	corev1 "k8s.io/api/core/v1"
)

type LoginPayload struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

type AuthResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}

func AuthenticateToVault(vaultAddr, jwt, role string) (string, error) {
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

func StoreKubeconfig(kubeconfigData corev1.Secret, client *vault.Client, secretPath, clusterName string) error {
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

func FetchKubeconfig(client *vault.Client, secretPath, clusterName string) (string, error) {
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
