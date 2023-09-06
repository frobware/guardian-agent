CMDS := sga-guard-bin sga-ssh sga-stub

all: $(CMDS)

$(CMDS):
	GO111MODULE=on go build -o cmd/$@ ./cmd/$@

install:
	@for cmd in $(CMDS); do \
		GO111MODULE=on go install ./cmd/$$cmd; \
	done

.PHONY: all install clean $(CMDS)

clean:
	$(RM) $(CMDS)
