T ?= all
.PHONY: up down reset build status test lint secrets rotate new add check \
        ports gen-cron scoreboard index capacity firewall install-hooks

up:         ; ./ctfctl up $(T)
down:       ; ./ctfctl down $(T)
reset:      ; ./ctfctl reset $(T)
build:      ; ./ctfctl build $(T)
status:     ; ./ctfctl status $(T)
test:       ; ./ctfctl test $(T)
lint:       ; ./ctfctl lint $(T)
secrets:    ; ./ctfctl secrets $(T)
rotate:     ; ./ctfctl rotate $(T)
check:      ; ./ctfctl lint all
ports:      ; ./ctfctl ports
gen-cron:   ; ./ctfctl gen-cron
scoreboard: ; ./ctfctl scoreboard
index:      ; ./ctfctl index
capacity:   ; ./ctfctl capacity
firewall:   ; ./ctfctl firewall
install-hooks: ; ./ctfctl install-hooks
