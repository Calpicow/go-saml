package saml

import "errors"

var (
	//ErrPEMFormat error with pem format
	ErrPEMFormat = errors.New("Certificate not valid pem format")
	//ErrInvalidSettings settings configuration does not allow for action
	ErrInvalidSettings = errors.New("SAML settings configuration does not permit this action")
	//ErrMissingID missing id attribute
	ErrMissingID = errors.New("Missing ID attribute on SAML Response")
	//ErrUnsupportedVersion saml version not supported
	ErrUnsupportedVersion = errors.New("Unsupported SAML Version")
	//ErrCannotDecode saml document
	ErrCannotDecode = errors.New("Unable to decode and/or decompress message")
)
