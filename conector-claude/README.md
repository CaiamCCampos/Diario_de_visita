# Conector do Diário Técnico para o Claude

Servidor MCP remoto (somente leitura) que deixa o Claude consultar o inventário e as
pendências do Diário Técnico — inclusive por voz, no app do celular.

Roda no **Cloudflare Workers (plano gratuito)** e lê o Firestore do projeto
`diario-visitas-controller` com uma conta de serviço que **só tem leitura**.
Nunca lê a coleção `inventarioAcessos` (logins e senhas), nem `usuarios` e `autorizacoes`.

## Ferramentas

| Ferramenta | Para perguntas como |
|---|---|
| `listar_clientes` | "Como estão todos os clientes?" / "Qual cliente tem a pior disponibilidade?" |
| `resumo_cliente` | "Quantos dispositivos tem a Ecolab?" / "Qual a porcentagem online do Thera?" |
| `dispositivos_por_status` | "Quais câmeras estão offline na Ecolab?" / "O que está em falha no Union?" |
| `pendencias_abertas` | "Quais pendências da Ecolab estão abertas há mais de 10 dias?" |
| `quadros_de_distribuicao` | "Como estão os quadros da Ecolab?" / "Quantas câmeras dependem do QD ETE?" |
| `buscar_dispositivo` | "Qual a situação da câmera 192.168.1.159 da Ecolab?" |

## Instalação (uma vez)

1. **Conta de serviço só de leitura** (Google Cloud, projeto `diario-visitas-controller`):
   IAM e administrador → Contas de serviço → Criar → nome `conector-claude` →
   papel **Cloud Datastore Viewer** → Chaves → Adicionar chave → JSON (baixa um arquivo).
   Não coloque esse arquivo no GitHub.
2. **Cloudflare** → Workers & Pages → Create application → importar do GitHub este
   repositório → **Root directory: `conector-claude`** → Save and Deploy.
   O nome do Worker precisa ser `diario-tecnico-conector` (igual ao `wrangler.toml`).
3. No Worker → Settings → Variables and Secrets → adicionar como **Secret**:
   - `FIREBASE_SA`: o conteúdo inteiro do arquivo .json
   - `ACESSO_TOKEN`: um texto aleatório longo (só letras e números)
4. **Claude** → Configurações → Conectores → Adicionar conector personalizado → endereço:
   `https://diario-tecnico-conector.<sua-conta>.workers.dev/mcp/<ACESSO_TOKEN>`

Depois disso, cada atualização deste diretório no GitHub é publicada sozinha pelo Cloudflare.

## Segurança

- Só leitura: a conta de serviço não tem permissão de escrita no Firestore.
- O endereço contém o `ACESSO_TOKEN`; sem ele o conector responde 401. Não compartilhe o endereço.
- Para trocar o acesso: gere outro `ACESSO_TOKEN` no Cloudflare e atualize o endereço no Claude.
- Para cortar o acesso ao banco: apague a chave da conta de serviço no Google Cloud.
