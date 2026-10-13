module github.com/MATII-Technologies/matii-sc/csi

go 1.26.0

toolchain go1.26.9

require (
	github.com/MATII-Technologies/matii-sc/go v0.0.0
	google.golang.org/grpc v1.84.0
	sigs.k8s.io/secrets-store-csi-driver v1.6.1
)

require (
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af // indirect
)

replace github.com/MATII-Technologies/matii-sc/go => ../go
