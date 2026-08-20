package rbac_tests

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// Helper to escape string literals safely for SQL trigger body
func quoteSQLLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// Helper to seed minimal valid test entity, policies, and venues in PostgreSQL if absent
func seedTestFixtures(t *testing.T, db *sql.DB, entityID, venueA, venueB, weakPolicyID, strongPolicyID string) {
	t.Helper()

	// Seed entity
	if _, err := db.Exec(`INSERT INTO entities (id, name, description) VALUES ($1, 'Test Entity A', 'Test Entity') ON CONFLICT (id) DO NOTHING`, entityID); err != nil {
		t.Fatalf("failed to seed test entity %s: %v", entityID, err)
	}

	// Seed weak policy
	if _, err := db.Exec(`INSERT INTO policies (id, name) VALUES ($1, 'Weak Policy') ON CONFLICT (id) DO NOTHING`, weakPolicyID); err != nil {
		t.Fatalf("failed to seed test policy %s: %v", weakPolicyID, err)
	}

	// Seed strong policy
	if _, err := db.Exec(`INSERT INTO policies (id, name) VALUES ($1, 'Strong Policy') ON CONFLICT (id) DO NOTHING`, strongPolicyID); err != nil {
		t.Fatalf("failed to seed test policy %s: %v", strongPolicyID, err)
	}

	// Seed venues belonging to entityA
	if _, err := db.Exec(`INSERT INTO venues (id, name, entity) VALUES ($1, 'Test Venue A', $3), ($2, 'Test Venue B', $3) ON CONFLICT (id) DO NOTHING`, venueA, venueB, entityID); err != nil {
		t.Fatalf("failed to seed test venues %s, %s: %v", venueA, venueB, err)
	}
}

// Installs a temporary DB trigger on the roles table to fail inserts/updates on failVenueID
func installRolesRollbackTrigger(t *testing.T, db *sql.DB, failVenueID string) {
	t.Helper()

	sqlText := `
CREATE OR REPLACE FUNCTION fail_roles_write_for_rollback_test()
RETURNS trigger AS $$
BEGIN
  IF NEW.venue = TG_ARGV[0] THEN
    RAISE EXCEPTION 'rollback test forced failure for venue %', NEW.venue;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS test_fail_roles_write ON roles;

CREATE TRIGGER test_fail_roles_write
BEFORE INSERT OR UPDATE ON roles
FOR EACH ROW
EXECUTE FUNCTION fail_roles_write_for_rollback_test(` + quoteSQLLiteral(failVenueID) + `);
`

	if _, err := db.Exec(sqlText); err != nil {
		t.Fatalf("failed to install rollback trigger: %v", err)
	}
}

// Cleans up the temporary test DB trigger and function
func cleanupRolesRollbackTrigger(t *testing.T, db *sql.DB) {
	t.Helper()

	_, err := db.Exec(`
DROP TRIGGER IF EXISTS test_fail_roles_write ON roles;
DROP FUNCTION IF EXISTS fail_roles_write_for_rollback_test();
`)
	if err != nil {
		t.Fatalf("failed to cleanup rollback trigger: %v", err)
	}
}

// Verifies directly via SQL query that no role is persisted for a user and venue
func assertNoRoleForVenue(t *testing.T, db *sql.DB, userID, venueID string) {
	t.Helper()

	var count int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM roles
		WHERE venue = $1
		  AND users LIKE '%' || $2 || '%'
	`, venueID, userID).Scan(&count)
	if err != nil {
		t.Fatalf("failed to query roles rollback state: %v", err)
	}

	if count != 0 {
		t.Fatalf("expected no persisted role for user %s venue %s after rollback, found %d", userID, venueID, count)
	}
}

// ============================================================================
// DATABASE TRANSACTION & ROLLBACK INTEGRITY TEST SUITE
// ============================================================================

/*
 * TestManagementRole_MultiScopeTransactionRollback
 *
 * API: POST /api/v1/managementRole/0
 *
 * DESCRIPTION:
 *   Validates atomic database transaction and rollback semantics during multi-venue role creation and update.
 *   Subtest 1 (Create Path): Tests that when creating a new multi-venue role assignment, a failure on the second venue
 *                           rolls back the newly created role for the first venue.
 *   Subtest 2 (Update Path): Tests that when updating an existing role on the first venue, a failure on the second venue
 *                           rolls back both policy and modified timestamp mutations on the first venue.
 */
func TestManagementRole_MultiScopeTransactionRollback(t *testing.T) {
	// Note: This test installs a temporary DB trigger on the roles table.
	// It must not run in parallel with other role-write tests using the rollback target venue.

	dbURL := getEnvOrDefault("OWPROV_TEST_DATABASE_URL", "")
	if dbURL == "" {
		t.Skip("OWPROV_TEST_DATABASE_URL is required for DB rollback trigger test")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("failed to ping test database: %v", err)
	}

	client := NewTestClient(getEnvOrDefault("OWPROV_URL", "https://localhost:16005/api/v1"))

	tokenRoot := getEnvOrDefault("TOKEN_ROOT", "Bearer dynamic-root-token")
	targetUserA := getEnvOrDefault("TARGET_USER_A", "00000000-0000-0000-0000-000000000001")
	entityA := getEnvOrDefault("OPERATOR_A_ENTITY_UUID", "7fa1a180-c93c-4b3b-a3ac-b3fbbf0fa097")
	validVenueA := getEnvOrDefault("VENUE_A_UUID", "22222222-2222-2222-2222-222222222222")
	validVenueB := getEnvOrDefault("VENUE_ROLLBACK_TEST_UUID", getEnvOrDefault("VENUE_B_UUID", "33333333-3333-3333-3333-333333333333"))
	weakPolicy := getEnvOrDefault("POLICY_WEAK_ID", "94bb61a3-aa3e-49aa-9704-cc254fec4482")
	strongPolicy := getEnvOrDefault("POLICY_STRONG_ID", "11bb61a3-aa3e-49aa-9704-cc254fec4482")

	// Ensure entity, policies, and venues exist in DB for self-contained execution
	seedTestFixtures(t, db, entityA, validVenueA, validVenueB, weakPolicy, strongPolicy)

	t.Run("Verify Multi-Venue Create Failure Triggers Transaction Rollback", func(t *testing.T) {
		// Baseline cleanup: remove pre-existing test roles for targetUserA on test venues
		_, err := db.Exec(`
			DELETE FROM roles
			WHERE venue IN ($1, $2)
			  AND users LIKE '%' || $3 || '%'
		`, validVenueA, validVenueB, targetUserA)
		if err != nil {
			t.Fatalf("failed to cleanup pre-existing test roles: %v", err)
		}

		// Ensure clean trigger state before installing
		cleanupRolesRollbackTrigger(t, db)
		installRolesRollbackTrigger(t, db, validVenueB)
		defer cleanupRolesRollbackTrigger(t, db)

		payload := map[string]interface{}{
			"name":             "create-rollback-test-role",
			"users":            []string{targetUserA},
			"entity":           entityA,
			"venueIds":         []string{validVenueA, validVenueB},
			"managementPolicy": weakPolicy,
		}

		status, body, err := client.DoRequest("POST", "/managementRole/0", tokenRoot, payload)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if status != http.StatusInternalServerError {
			t.Fatalf("expected 500 from DB trigger failure inside transaction, got %d. Body: %s", status, string(body))
		}

		// Direct SQL DB assertions to verify atomicity & complete rollback
		assertNoRoleForVenue(t, db, targetUserA, validVenueA)
		assertNoRoleForVenue(t, db, targetUserA, validVenueB)
	})

	t.Run("Verify Multi-Venue Existing Role Update Failure Rolls Back Mutation", func(t *testing.T) {
		// Baseline cleanup: remove pre-existing test roles for targetUserA on test venues
		_, err := db.Exec(`
			DELETE FROM roles
			WHERE venue IN ($1, $2)
			  AND users LIKE '%' || $3 || '%'
		`, validVenueA, validVenueB, targetUserA)
		if err != nil {
			t.Fatalf("failed to cleanup pre-existing test roles: %v", err)
		}

		// Step 1: Create baseline existing role for validVenueA through the API so the update path uses production-created data.
		baselinePayload := map[string]interface{}{
			"name":             "baseline-role-venue-a",
			"users":            []string{targetUserA},
			"entity":           entityA,
			"venueIds":         []string{validVenueA},
			"managementPolicy": weakPolicy,
		}

		status, body, err := client.DoRequest("POST", "/managementRole/0", tokenRoot, baselinePayload)
		if err != nil {
			t.Fatalf("failed to send baseline role creation request: %v", err)
		}
		if status != http.StatusOK {
			t.Fatalf("expected 200 for baseline role creation on venue A, got %d. Body: %s", status, string(body))
		}

		// Fetch existing role ID and initial modified timestamp via SQL
		var existingRoleID string
		var initialModified int64
		err = db.QueryRow(`
			SELECT id, modified FROM roles
			WHERE venue = $1 AND users LIKE '%' || $2 || '%'
		`, validVenueA, targetUserA).Scan(&existingRoleID, &initialModified)
		if err != nil {
			t.Fatalf("failed to query created baseline role from DB: %v", err)
		}

		defer func() {
			_, _ = db.Exec(`DELETE FROM roles WHERE id = $1`, existingRoleID)
		}()

		// Step 2: Ensure clean trigger state, then install failure trigger on validVenueB
		cleanupRolesRollbackTrigger(t, db)
		installRolesRollbackTrigger(t, db, validVenueB)
		defer cleanupRolesRollbackTrigger(t, db)

		// Step 3: Send multi-venue request to update policy to strongPolicy for both validVenueA and validVenueB
		updatePayload := map[string]interface{}{
			"name":             "update-rollback-test-role",
			"users":            []string{targetUserA},
			"entity":           entityA,
			"venueIds":         []string{validVenueA, validVenueB},
			"managementPolicy": strongPolicy,
		}

		status, body, err = client.DoRequest("POST", "/managementRole/0", tokenRoot, updatePayload)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if status != http.StatusInternalServerError {
			t.Fatalf("expected 500 from DB trigger failure inside transaction, got %d. Body: %s", status, string(body))
		}

		// Step 4: Direct SQL DB assertions: verify existing role for validVenueA retained original policy AND modified timestamp
		var currentPolicy string
		var currentModified int64
		err = db.QueryRow(`
			SELECT managementpolicy, modified
			FROM roles
			WHERE id = $1
		`, existingRoleID).Scan(&currentPolicy, &currentModified)
		if err != nil {
			t.Fatalf("failed to query existing role state after rollback: %v", err)
		}

		if currentPolicy != weakPolicy {
			t.Fatalf("expected existing role on venue %s to retain original policy %s after rollback, got %s", validVenueA, weakPolicy, currentPolicy)
		}

		if currentModified != initialModified {
			t.Fatalf("expected existing role on venue %s to retain original modified timestamp %d after rollback, got %d", validVenueA, initialModified, currentModified)
		}

		// Direct SQL DB assertion: verify no role was created for validVenueB
		assertNoRoleForVenue(t, db, targetUserA, validVenueB)
	})
}
