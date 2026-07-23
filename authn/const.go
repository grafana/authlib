package authn

const (
	metadataKeyAccessToken     = "X-Access-Token"
	metadataKeyIDTokenMetadata = "X-Id-Token"

	httpHeaderAccessToken = "X-Access-Token"
	httpHeaderIDToken     = "X-Grafana-Id"

	OAuthPassthroughAccessTokenHeader = "X-OAuth-Passthrough-Access-Token"
	OAuthPassthroughIDTokenHeader     = "X-OAuth-Passthrough-ID-Token"

	ServiceIdentityKey          = "serviceIdentity"
	InnermostServiceIdentityKey = "innermostServiceIdentity"
)
