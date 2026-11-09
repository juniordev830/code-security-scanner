# Code Security Scanner

Analisador estático **somente leitura**, baseado em regras; procura construções que merecem revisão em Python/JavaScript/TypeScript. Emite JSON com arquivo, linha, severidade e regra.

## Estado

**MVP funcional / projeto inicial de portfólio.** Implementa o núcleo descrito abaixo, mas não é produto pronto para produção.

## Como executar

```bash
python scanner.py ./meu-projeto
python scanner.py ./meu-projeto --exclude fixtures --fail-on medium
python scanner.py ./meu-projeto --format sarif > scan-results.sarif
```

Use `--exclude` com nomes de pastas para ignorar diretórios adicionais em qualquer nível. O argumento pode ser repetido. Com `--fail-on medium`, achados médios e altos retornam código 1. O padrão continua sendo `high`, e `none` mantém código 0 quando há achados.

## Testes

```bash
python -m unittest discover -s tests -v
```

O GitHub Actions executa os testes automaticamente em pushes e pull requests.

## Segurança e limitações

Regras simples geram falsos positivos e falsos negativos; nunca executa os arquivos. As regras `PY-EVAL` e `PY-SHELL` são aplicadas somente a Python, enquanto `WEB-INNERHTML` verifica JavaScript/TypeScript (inclusive JSX/TSX). O scanner utiliza a tokenização do Python para ignorar comentários e strings comuns, mantendo a numeração das linhas. Não é uma análise semântica: chamadas via alias, expressões dentro de f-strings e sintaxe inválida podem escapar da detecção; regras web continuam heurísticas. Não percorre dependências, pastas excluídas ou links simbólicos para diretórios. Ignora arquivos >256 KB. Não substitui Semgrep, SAST nem auditoria de segurança.

## Evolução planejada

Integrar Semgrep e scanners de dependências, supressões justificadas e integração automática da saída SARIF já disponível com o GitHub Code Scanning.

---
Projeto de Engenharia de Software mantido na conta [juniordev830](https://github.com/juniordev830).
