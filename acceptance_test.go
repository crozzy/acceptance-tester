package acceptancetesttester_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/acceptance"
	"github.com/quay/claircore/test/integration"
	testpostgres "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/toolkit/fixtures"
)

type vexFeedTest struct {
	Name    string
	Image   string
	VEXURLs []string
	Expect  []fixtures.ManifestRecord
}

var vexTests = []vexFeedTest{
	// Vulnerable UBI9 9.0.0 — glibc (Looney Tunables) and openssl are affected.
	{
		Name:  "UBI9_90_Vulnerable",
		Image: "registry.access.redhat.com/ubi9:9.0.0",
		VEXURLs: []string{
			"https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-4911.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-2650.json",
		},
		Expect: []fixtures.ManifestRecord{
			{ID: "CVE-2023-4911", Product: "BaseOS-9.2.0.Z.MAIN.EUS:glibc-0:2.34-60.el9_2.7.aarch64", Status: fixtures.StatusAffected},
			{ID: "CVE-2023-2650", Product: "BaseOS-9.2.0.Z.MAIN.EUS:openssl-libs-1:3.0.7-16.el9_2.aarch64", Status: fixtures.StatusAffected},
		},
	},
	// Patched UBI9 9.3 — same CVEs should be absent after the fix.
	{
		Name:  "UBI9_93_Patched",
		Image: "registry.access.redhat.com/ubi9:9.3",
		VEXURLs: []string{
			"https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-4911.json",
			"https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-2650.json",
		},
		Expect: []fixtures.ManifestRecord{
			{ID: "CVE-2023-4911", Product: "BaseOS-9.2.0.Z.MAIN.EUS:glibc-0:2.34-60.el9_2.7.aarch64", Status: fixtures.StatusAbsent},
			{ID: "CVE-2023-2650", Product: "BaseOS-9.2.0.Z.MAIN.EUS:openssl-libs-1:3.0.7-16.el9_2.aarch64", Status: fixtures.StatusAbsent},
		},
	},
}

func TestVEXFeeds(t *testing.T) {
	integration.Skip(t)
	integration.NeedDB(t)
	ctx := test.Logging(t)

	indexerPool := testpostgres.TestIndexerDB(ctx, t)
	matcherPool := testpostgres.TestMatcherDB(ctx, t)
	client := &http.Client{Timeout: 2 * time.Minute}

	auditor, err := acceptance.NewClaircoreAuditor(ctx, t, &acceptance.ClaircoreConfig{
		IndexerPool: indexerPool,
		MatcherPool: matcherPool,
	}, client)
	if err != nil {
		t.Fatalf("NewClaircoreAuditor: %v", err)
	}
	t.Cleanup(func() { auditor.Close(ctx) })

	for _, tc := range vexTests {
		t.Run(tc.Name, func(t *testing.T) {
			docs, err := acceptance.FetchVEXDocs(ctx, client, tc.VEXURLs)
			if err != nil {
				t.Fatalf("fetch VEX: %v", err)
			}
			fix := &acceptance.Fixture{
				Reference:    tc.Image,
				VEXDocuments: docs,
				Expected:     tc.Expect,
			}
			acceptance.Run(ctx, t, auditor, []string{tc.Image}, acceptance.WithFixture(fix))
		})
	}
}
