Сценарий CI для GitHub Actions (сборка, тесты, короткий soak на self-hosted Windows-агенте
с установленной Delphi 12).

Чтобы включить: скопируйте github-actions-ci.yml в .github/workflows/ci.yml и отправьте коммит
(для отправки файлов workflow токену GitHub нужно право «workflow»:
`gh auth refresh -s workflow`). Без self-hosted агента с Delphi сборка в CI не запустится.
