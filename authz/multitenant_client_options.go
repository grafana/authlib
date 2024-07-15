package authz

import (
	"google.golang.org/grpc"

	"github.com/grafana/authlib/cache"
)

func WithCacheMTCOption(cache cache.Cache) MultiTenantClientOption {
	return func(c *LegacyClientImpl) error {
		c.cache = cache
		return nil
	}
}

func WithGrpcClientMTCOptions(opts ...grpc.DialOption) MultiTenantClientOption {
	return func(c *LegacyClientImpl) error {
		var err error
		c.clientV1, err = newGRPCClient(c.authCfg.remoteAddress, opts...)
		return err
	}
}
