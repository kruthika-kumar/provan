ARG RUNNER_IMAGE
FROM ${RUNNER_IMAGE}
RUN addgroup -g 65532 supervisor && adduser -D -H -u 65532 -G supervisor supervisor && adduser -D -H -u 65533 -G supervisor patient && mkdir -p /supervisor /gateway /output && chown supervisor:supervisor /supervisor && chmod 0700 /supervisor && chmod 1777 /output
COPY patient_launcher.py /gateway/patient-launcher
COPY patient_reaper.py /gateway/patient-reaper
COPY supervisor.py quiescence_probe.py transfer_helper.py /supervisor/
RUN chown supervisor:supervisor /supervisor/* && chmod 0700 /supervisor/* && chown root:root /gateway/* && chmod 0555 /gateway/*
USER 65532:65532
ENTRYPOINT ["/supervisor/supervisor.py"]
