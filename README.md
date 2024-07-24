# JWT em Go

Este pacote Go facilita a criação e validação de JSON Web Tokens (JWTs). Ele oferece funções para a serialização e desserialização de tokens JWT com base em um cabeçalho e uma carga útil.

> A implementação atual não foi revisada profundamente. Agradeço se qualquer problema for relatado na seção [Issues](https://github.com/othon-hugo/go-jwt/issues) do repositório.

## Função `Marshal`

```go
func Marshal(header Header, claims any, secret []byte) (string, error)
```

- **Descrição**: Gera um JWT a partir do cabeçalho, carga útil e chave secreta fornecidos. Retorna o token JWT codificado como uma `string`.

- **Parâmetros**:
  - `header`: Estrutura `Header` que define o cabeçalho do JWT, incluindo o algoritmo e o tipo.
  - `claims`: Dados da carga útil a serem incluídos no JWT.
  - `secret`: Chave secreta usada para assinar o JWT.

- **Retorno**:
  - `string`: Token JWT codificado.
  - `error`: Retorna um erro em caso de falha na operação.

## Função `Unmarshal`

```go
func Unmarshal(jws string, claims any, secret []byte) error
```

- **Descrição**: Decodifica e valida um token JWT, preenchendo a estrutura de carga útil fornecida com os dados do token. Também verifica a compatibilidade do tipo do token.

- **Parâmetros**:
  - `jws`: Token JWT codificado a ser decodificado.
  - `claims`: Estrutura onde os dados da carga útil serão preenchidos.
  - `secret`: Chave secreta usada para validar o JWT.

- **Retorno**:
  - `error`: Retorna um erro se a operação falhar ou se o tipo do token não for suportado.

## Estrutura `Header`

A estrutura `Header` é utilizada com a função `Marshal()` para definir o cabeçalho do JWT.

```go
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}
```

- **Campo `Alg`**: Algoritmo de assinatura do JWT.
- **Campo `Typ`**: Tipo do token JWT (deve ser `JWT`).

## Constantes e Erros

O pacote define as seguintes constantes para algoritmos JWT:

- `HS256`: Algoritmo HMAC com SHA-256.
- `HS384`: Algoritmo HMAC com SHA-384.
- `HS512`: Algoritmo HMAC com SHA-512.

O pacote também define uma constante para o tipo JWT:

- `JWT`: Tipo de token JWT.

Além disso, define as seguintes variáveis de erro:

- `ErrInvalidToken`: Erro quando o token JWT é inválido.
- `ErrSignatureMismatch`: Erro quando a assinatura do JWT não corresponde durante a verificação.

### Estruturas de Erro Personalizadas

#### Estrutura `UnsupportedAlgorithmError`

```go
type UnsupportedAlgorithmError struct{}
```

- **Descrição**: Erro retornado quando um algoritmo não suportado é utilizado.

#### Estrutura `UnsupportedTypeError`

```go
type UnsupportedTypeError struct{}
```

- **Descrição**: Erro retornado quando o tipo do token JWT não é suportado.

## Exemplo de Uso

### Exemplo de Criação e Validação de JWT

```go
// Ignora outros imports para melhorar a legibilidade
import "github.com/othon-hugo/go-jwt/pkg/jwt"

type Claims struct {
	UserID    string `json:"user_id"`
	ExpiresAt int64  `json:"exp"`
}

func main() {
	// Cabeçalho do JWT
	header := jwt.Header{
		Alg: jwt.HS256,
		Typ: jwt.JWT,
	}

	// Dados da carga útil
	claims := Claims{
		UserID:    "1234567890",
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}

	// Chave secreta para assinatura
	secret := []byte("you-will-never-know-my-secret :D")

	// Criando o token JWT
	token, err := jwt.Marshal(header, claims, secret)

	if err != nil {
		log.Fatalf("Erro ao criar o JWT: %v", err)
	}

	fmt.Printf("Token JWT criado: %s\n", token)

	// Estrutura para armazenar os dados decodificados
	var decodedClaims Claims

	// Validando e decodificando o token JWT
	err = jwt.Unmarshal(token, &decodedClaims, secret)

	if err != nil {
		log.Fatalf("Erro ao validar o JWT: %v", err)
	}

	fmt.Printf("Dados decodificados: %+v\n", decodedClaims)
}
```