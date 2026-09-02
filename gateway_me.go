// gateway_me.go wraps GET /v1/me: the account's free allowance, balances, and
// quota packages — the data behind both `u1s1 usage` and the management panel.
package main

import (
	"encoding/json"
	"fmt"
)

type meResponse struct {
	Email                 string  `json:"email"`
	SignupCreditUSD       float64 `json:"signup_credit_usd"`
	DailyFreeUSD          float64 `json:"daily_free_usd"`
	DailyFreeUsedUSD      float64 `json:"daily_free_used_usd"`
	DailyFreeRemainingUSD float64 `json:"daily_free_remaining_usd"`
	DailyFreeResetsAt     string  `json:"daily_free_resets_at"`
	DailyFreeModel        string  `json:"daily_free_model"`
	MonthlyFreeUSD        float64 `json:"monthly_free_usd"`
	MTDUSD                float64 `json:"mtd_usd"`
	BalanceSpentUSD       float64 `json:"balance_spent_usd"`
	BonusBalanceUSD       float64 `json:"bonus_balance_usd"`
	RemainingUSD          float64 `json:"remaining_usd"`
	// FreeClaim is "first" (signup package) or "renew" (yearly package) when the
	// account has a free quota package waiting to be claimed on the website, and
	// null/absent otherwise.
	FreeClaim    string           `json:"free_claim"`
	TokensPerUSD float64          `json:"tokens_per_usd"`
	Packages     []gatewayPackage `json:"packages"`
}

// gatewayPackage is one quota package as reported by /v1/me.
type gatewayPackage struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind"`
	Scope       string `json:"scope"`
	DailyTokens *int64 `json:"daily_tokens"`
	TotalTokens *int64 `json:"total_tokens"`
	UsedToday   int64  `json:"used_today"`
	UsedTokens  int64  `json:"used_tokens"`
	Remaining   int64  `json:"remaining"`
	ExpiresAt   string `json:"expires_at"`
	Note        string `json:"note"`
	CreatedAt   string `json:"created_at"`
}

func fetchMe(sa storedAuth, attestation, callbackID string) (*meResponse, error) {
	url := sa.baseURL() + "/me"
	headers, err := signedHeaders(sa, "GET", url, attestation)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest("GET", url, headers, nil, callbackID)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("u1s1 me: %s", gatewayMessage(resp.Body, resp.StatusCode))
	}
	var decoded meResponse
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		return nil, fmt.Errorf("u1s1 me: decode: %w", err)
	}
	return &decoded, nil
}
