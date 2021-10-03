build:
	goreleaser build --single-target --rm-dist

release:
	goreleaser release
