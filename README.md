# Code Security Scanner

Analisador estático **somente leitura**, baseado em regras; procura construções que merecem revisão em Python/JavaScript/TypeScript. Emite JSON ou SARIF com arquivo, linha, severidade e regra. Regras Python são aplicadas apenas a `.py`, e as regras JavaScript/TypeScript apenas aos respectivos arquivos.

## Estado

**MVP funcional / projeto inicial de portfólio.** Implementa o núcleo descrito abaixo, mas não é produto pronto para produção.

## Como executar

```bash
python scanner.py ./meu-projeto
python scanner.py ./meu-projeto --exclude fixtures --fail-on medium
python scanner.py ./meu-projeto --format sarif --fail-on none > report.sarif
```

Use `--exclude` com nomes de pastas para ignorar diretórios adicionais em qualquer nível. O argumento pode ser repetido. Com `--fail-on medium`, achados médios e altos retornam código 1. O padrão continua sendo `high`, e `none` mantém código 0 quando há achados.

## Testes

```bash
python -m unittest discover -s tests -v
```

O GitHub Actions executa os testes automaticamente em pushes e pull requests.

## Segurança e limitações

Regras simples geram falsos positivos e falsos negativos; nunca executa os arquivos. Para JavaScript e TypeScript, comentários, strings entre aspas e textos literais de templates são mascarados sem remover expressões executáveis dentro de `${...}`. Arquivos com sintaxe incompleta voltam à busca conservadora pelo texto bruto. A análise não é um parser AST completo e expressões regulares ou sintaxes ambíguas ainda podem gerar imprecisão. Para Python, o scanner mascara strings e comentários sem esconder expressões executáveis de f-strings (por exemplo, `f"{eval(data)}"`). Em Python 3.12+, trechos literais de f-strings são mascarados individualmente; versões antigas preservam a f-string inteira para evitar falsos negativos, o que pode aumentar falsos positivos. Ignora dependências e arquivos >256 KB. Não substitui Semgrep, SAST nem auditoria de segurança.

## Evolução planejada

Integrar Semgrep e scanners de dependências, supressões justificadas e configuração de upload dos relatórios SARIF para o GitHub Code Scanning.

---
Projeto de Engenharia de Software mantido na conta [juniordev830](https://github.com/juniordev830).
