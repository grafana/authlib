package authz

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type MockClient struct {
	mock.Mock
}

func (_m *MockClient) Search(ctx context.Context, query SearchQuery) (*SearchResponse, error) {
	ret := _m.Called(ctx, query)

	var r0 *SearchResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, SearchQuery) (*SearchResponse, error)); ok {
		return rf(ctx, query)
	}
	if rf, ok := ret.Get(0).(func(context.Context, SearchQuery) *SearchResponse); ok {
		r0 = rf(ctx, query)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*SearchResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, SearchQuery) error); ok {
		r1 = rf(ctx, query)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
