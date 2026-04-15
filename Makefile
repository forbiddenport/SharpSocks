IMAGE = sharpsocks-build

.PHONY: all clean

all:
	@sudo docker build -t $(IMAGE) .
	@rm -rf dist && CID=$$(sudo docker create $(IMAGE)) && \
		sudo docker cp $$CID:/dist ./dist && sudo docker rm $$CID >/dev/null && \
		sudo chown -R $$(id -u):$$(id -g) dist
	@find dist -type f | sort && echo "build complete -> dist/"

clean:
	@rm -rf dist && sudo docker rmi $(IMAGE) 2>/dev/null || true
