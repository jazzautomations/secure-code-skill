.PHONY: test scan help

help:
	@echo "make test          # roda a suíte de testes do scanner"
	@echo "make scan          # scan white-box do diretório atual"
	@echo "make scan URL=...  # scan black-box de um alvo (ex: make scan URL=https://exemplo.com)"

test:
	@bash tests/run.sh

scan:
	@bash scan.sh $(if $(URL),--url $(URL)) .
