ARG BUILDER_IMAGE
ARG RUNNER_IMAGE
FROM ${BUILDER_IMAGE} AS build
WORKDIR /build
COPY patient-launcher.c patient-reaper.c ./
RUN cc -O2 -Wall -Werror -o patient-launcher patient-launcher.c && cc -O2 -Wall -Werror -o patient-reaper patient-reaper.c

FROM ${RUNNER_IMAGE}
RUN addgroup -g 65532 supervisor && adduser -D -H -u 65532 -G supervisor supervisor && addgroup -g 65533 patient && adduser -D -H -u 65533 -G patient patient && mkdir -p /supervisor /gateway /output && chown supervisor:supervisor /supervisor && chmod 0700 /supervisor && chmod 1777 /output
COPY --from=build /build/patient-launcher /gateway/patient-launcher
COPY --from=build /build/patient-reaper /gateway/patient-reaper
COPY supervisor.py quiescence_probe.py transfer_helper.py /supervisor/
RUN chown supervisor:supervisor /supervisor/* && chmod 0700 /supervisor/* && chown root:root /gateway/* && chmod 0111 /gateway/*
USER 65532:65532
ENTRYPOINT ["/supervisor/supervisor.py"]
