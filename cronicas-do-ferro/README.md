# Crônicas do Ferro — Cloud v3

RPG 8-bit mobile-first com autenticação própria e save na nuvem.

## Stack
- Frontend HTML5 Canvas/PWA
- Node.js + Express
- PostgreSQL
- Cookie HttpOnly + JWT
- bcrypt (12 rounds)

## Variáveis de ambiente
- `DATABASE_URL`
- `SESSION_SECRET` (mínimo 32 caracteres)
- `NODE_ENV=production`

## Segurança
- senha armazenada somente como hash bcrypt
- cookie de sessão HttpOnly, Secure em produção e SameSite=Lax
- rate limiting em login/cadastro e escrita de save
- Helmet/CSP
- sem coleta de e-mail, idade ou dados financeiros

## Save
O jogo salva localmente e, quando autenticado, também sincroniza com PostgreSQL. Ao entrar em outro aparelho, o save mais recente entre navegador e nuvem é usado.
