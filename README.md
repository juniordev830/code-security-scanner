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

Regras simples geram falsos positivos e falsos negativos; nunca executa os arquivos. As regras `PY-EVAL` e `PY-SHELL` são aplicadas somente a Python, enquanto `WEB-INNERHTML` verifica JavaScript/TypeScript (inclusive JSX/TSX). Em arquivos Python com sintaxe válida, utiliza a AST para detectar chamadas (inclusive nas expressões de f-strings), evitando falsos positivos de atribuições e declarações. Quando não é possível analisar a sintaxe, usa um fallback lexical que mascara strings e comentários. Não executa o código analisado. Mantém a numeração das linhas. Não é uma análise de fluxo: aliases e chamadas dinâmicas ainda podem escapar, e arquivos com sintaxe inválida recebem apenas uma verificação heurística. Regras web continuam heurísticas. Não percorre dependências, pastas excluídas ou links simbólicos para diretórios. Ignora arquivos >256 KB. Não substitui Semgrep, SAST nem auditoria de segurança.

## Evolução planejada

Integrar Semgrep e scanners de dependências, supressões justificadas e integração automática da saída SARIF já disponível com o GitHub Code Scanning.

---
Projeto de Engenharia de Software mantido na conta [juniordev830](https://github.com/juniordev830).

## Verificação antes de contribuir

O [guia de validação](docs/GUIA_DE_VALIDACAO.md) descreve o estado do código, as verificações reproduzíveis e os riscos a observar ao revisar novas alterações.
