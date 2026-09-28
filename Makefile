# Thin sugar over ./ctfctl. Usage: make up | make status | make test | make T=web-jwtopia up
T ?= all

.PHONY: up down reset build status test ports firewall scoreboard

up:         ; ./ctfctl up $(T)
down:       ; ./ctfctl down $(T)
reset:      ; ./ctfctl reset $(T)
build:      ; ./ctfctl build $(T)
status:     ; ./ctfctl status $(T)
test:       ; ./ctfctl test $(T)
ports:      ; ./ctfctl ports
firewall:   ; ./ctfctl firewall
scoreboard: ; ./ctfctl scoreboard
