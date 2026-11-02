# Code Security Scanner

Analisador estático **somente leitura**, baseado em regras; procura construções que merecem revisão em Python/JavaScript/TypeScript. Emite JSON com arquivo, linha, severidade e regra.

## Estado

**MVP funcional / projeto inicial de portfólio.** Implementa o núcleo descrito abaixo, mas não é produto pronto para produção.

## Como executar

```bash
python scanner.py ./meu-projeto
```

## Testes

```bash
python -m unittest discover -s tests -v
```

O GitHub Actions executa os testes automaticamente em pushes e pull requests.

## Segurança e limitações

Regras simples geram falsos positivos e falsos negativos; nunca executa os arquivos. Ignora dependências e arquivos >256 KB. Não substitui Semgrep, SAST nem auditoria de segurança.

## Evolução planejada

Integrar Semgrep e scanners de dependências, supressões justificadas e saída SARIF para GitHub Code Scanning.

---
Projeto de Engenharia de Software mantido na conta [juniordev830](https://github.com/juniordev830).
