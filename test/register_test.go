package test

import (
	"context"
	_"server/internal/storage"
	"testing"

	"github.com/stretchr/testify/mock"
)

type MockUserStorage struct{
	mock.Mock
}
func(m *MockUserStorage) UserExists(ctx context.Context,email string)(bool,error){

	args:=m.Called(ctx,email)
	return args.Bool(0),args.Error(1)
}
func TestValidateRegister(t *testing.T){

	

	
} 