# WanHound test bench: a target with known per-port behavior.
# The firewall rules live inside the container's own network namespace
# (NET_ADMIN on the container only), so the host firewall is untouched.
FROM alpine:3.22
RUN apk add --no-cache python3 iptables
COPY bench.py /bench.py
CMD ["python3", "-u", "/bench.py"]
