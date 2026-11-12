# Operação e qualidade — Code Security Scanner

## Escopo existente

Scanner estático somente leitura de construções suspeitas em Python, JS e TS, com saída JSON/SARIF.

## Código e testes

`scanner.py`, `tests/test_scanner.py`, `tests/test_pruned_walk.py`, `tests/test_options.py`.

## Reprodução local

`python -m unittest discover -s tests -v`; `python scanner.py . --exclude tests --format sarif`.

Ao alterar funcionalidade, registrar no PR os comandos executados e os resultados; não tratar verificações não executadas como aprovadas.

## Cenários a incluir na regressão

Testar symlinks, diretórios ignorados, limites de tamanho, encoding inválido, false positives e o código de saída de `--fail-on`.

## Riscos e evolução

O resultado é triagem, não garantia de segurança. Não exibir achados com segredos em logs, nem executar arquivos inspecionados.

### Checklist de entrega

- [ ] Novo comportamento ligado a caso de uso real.
- [ ] Testes e exemplo documentados, quando aplicável.
- [ ] Nenhum segredo ou dado de cliente adicionado.
- [ ] Código revisado em branch, sem merge automático.
