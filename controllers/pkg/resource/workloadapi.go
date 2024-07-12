package resource

import (
	"context"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

func GetJWT(ctx context.Context) (*jwtsvid.SVID, error) {
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
