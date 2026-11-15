package digest_test

import (
	"context"
	"fmt"
	"github.com/PabloMz85/watchtower/internal/actions/mocks"
	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/registry/auth"
	"github.com/PabloMz85/watchtower/pkg/registry/digest"
	wtTypes "github.com/PabloMz85/watchtower/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"os"
	"testing"
	"time"
)

var suiteT *testing.T

func TestDigest(t *testing.T) {
	suiteT = t
	RegisterFailHandler(Fail)
	RunSpecs(GinkgoT(), "Digest Suite")
}

var (
	DockerHubCredentials = &wtTypes.RegistryCredentials{
		Username: os.Getenv("CI_INTEGRATION_TEST_REGISTRY_DH_USERNAME"),
		Password: os.Getenv("CI_INTEGRATION_TEST_REGISTRY_DH_PASSWORD"),
	}
	GHCRCredentials = &wtTypes.RegistryCredentials{
		Username: os.Getenv("CI_INTEGRATION_TEST_REGISTRY_GH_USERNAME"),
		Password: os.Getenv("CI_INTEGRATION_TEST_REGISTRY_GH_PASSWORD"),
	}
)

func SkipIfCredentialsEmpty(credentials *wtTypes.RegistryCredentials, fn func()) func() {
	if credentials.Username == "" {
		return func() {
			Skip("Username missing. Skipping integration test")
		}
	} else if credentials.Password == "" {
		return func() {
			Skip("Password missing. Skipping integration test")
		}
	} else {
		return fn
	}
}

var _ = Describe("Digests", func() {
	mockId := "mock-id"
	mockName := "mock-container"
	mockImage := "ghcr.io/k6io/operator:latest"
	mockCreated := time.Now()
	mockDigest := "ghcr.io/k6io/operator@sha256:d68e1e532088964195ad3a0a71526bc2f11a78de0def85629beb75e2265f0547"

	mockContainer := mocks.CreateMockContainerWithDigest(
		mockId,
		mockName,
		mockImage,
		mockCreated,
		mockDigest)

	mockContainerNoImage := mocks.CreateMockContainerWithImageInfoP(mockId, mockName, mockImage, mockCreated, nil)

	When("a digest comparison is done", func() {
		It("should return true if digests match",
			SkipIfCredentialsEmpty(GHCRCredentials, func() {
				creds := fmt.Sprintf("%s:%s", GHCRCredentials.Username, GHCRCredentials.Password)
				matches, err := digest.CompareDigest(mockContainer, creds)
				Expect(err).NotTo(HaveOccurred())
				Expect(matches).To(Equal(true))
			}),
		)

		It("should return false if digests differ", func() {

		})
		It("should return an error if the registry isn't available", func() {

		})
		It("should return an error when container contains no image info", func() {
			matches, err := digest.CompareDigest(mockContainerNoImage, `user:pass`)
			Expect(err).To(HaveOccurred())
			Expect(matches).To(Equal(false))
		})
	})
	When("using different registries", func() {
		It("should work with DockerHub",
			SkipIfCredentialsEmpty(DockerHubCredentials, func() {
				fmt.Println(DockerHubCredentials != nil) // to avoid crying linters
			}),
		)
		It("should work with GitHub Container Registry",
			SkipIfCredentialsEmpty(GHCRCredentials, func() {
				fmt.Println(GHCRCredentials != nil) // to avoid crying linters
			}),
		)
	})
	When("sending a HEAD request", func() {
		It("should use a custom user-agent over trusted TLS", func() {
			server, ca := registrytest.New(suiteT, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Header.Get("User-Agent")).To(Equal("Watchtower/v0.0.0-unknown"))
				w.Header().Set(digest.ContentDigestHeader, mockDigest)
			}))
			provider, err := auth.NewClient(auth.ClientOptions{CAFile: ca})
			Expect(err).NotTo(HaveOccurred())
			defer provider.Close()
			client, err := digest.NewClient(provider)
			Expect(err).NotTo(HaveOccurred())
			dig, err := client.GetDigest(context.Background(), server.URL, registrytest.Random(suiteT))
			Expect(err).NotTo(HaveOccurred())
			Expect(dig).To(Equal(mockDigest))
		})
	})
})
