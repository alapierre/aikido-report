# The binary is built by GoReleaser (CGO_ENABLED=0, static); this image
# only packages it. distroless/static ships CA certificates and nothing
# else — no shell, no package manager.
#
# The image intentionally runs as root (no :nonroot variant): as a
# Bitbucket pipe it must WRITE the SARIF report into the mounted clone
# directory, whose contents are owned by the (userns-remapped) root of the
# build container. See README "Use as a Bitbucket Pipe".
FROM gcr.io/distroless/static-debian12:latest

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/aikido-report /usr/local/bin/aikido-report

ENTRYPOINT ["/usr/local/bin/aikido-report"]
