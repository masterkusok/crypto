# crypto
Golang library, that implements several cryptographical algorithms.

## Структура проекта

```
crypto/
├── bits/           # Функции для работы с битами и перестановками
├── cipher/         # Криптографические алгоритмы и режимы шифрования
│   ├── des/       # Реализация DES
│   └── deal/      # Реализация DEAL
├── errors/         # Константные ошибки
├── tables/         # Таблицы перестановок и S-блоки для DES
└── examples/       # Примеры использования

```

## Реализованные компоненты

### 1. Перестановка битов (bits/bits.go)

Функция `Permute` выполняет перестановку битов в массиве байтов согласно P-блоку с поддержкой:
- Индексации от младшего к старшему биту (LSBFirst) или наоборот (MSBFirst)
- Нумерации битов с 0 или с 1

```go
data := []byte{0x12, 0x34}
pTable := []int{1, 2, 3, 4, 5, 6, 7, 8}
result, err := bits.Permute(data, pTable, bits.MSBFirst, bits.StartFromOne)
```

### 2. Интерфейсы (cipher/interfaces.go)

#### KeyScheduler
Генерирует раундовые ключи из основного ключа:
```go
type KeyScheduler interface {
    GenerateRoundKeys(ctx context.Context, key []byte) ([][]byte, error)
}
```

#### RoundFunction
Выполняет раундовое преобразование:
```go
type RoundFunction interface {
    Transform(ctx context.Context, block, roundKey []byte) ([]byte, error)
}
```

#### BlockCipher
Предоставляет функционал шифрования/дешифрования:
```go
type BlockCipher interface {
    SetKey(ctx context.Context, key []byte) error
    Encrypt(ctx context.Context, block []byte) ([]byte, error)
    Decrypt(ctx context.Context, block []byte) ([]byte, error)
    BlockSize() int
}
```

### 3. Сеть Фейстеля (cipher/feistel.go)

Класс `FeistelNetwork` реализует структуру сети Фейстеля, принимая в конструкторе:
- KeyScheduler - для генерации раундовых ключей
- RoundFunction - для выполнения раундовых преобразований
- Размер блока

### 4. Алгоритм DES (cipher/des/des.go)

Полная реализация DES на базе сети Фейстеля:
- `KeyScheduler` - генерация 16 раундовых ключей с использованием PC1, PC2 и циклических сдвигов
- `RoundFunction` - функция F с расширением, S-блоками и P-перестановкой
- Начальная и конечная перестановки (IP и FP)

```go
des := des.NewDES()
err := des.SetKey(ctx, key) // 8 байт
encrypted, err := des.Encrypt(ctx, plaintext) // 8 байт
decrypted, err := des.Decrypt(ctx, encrypted)
```

### 5. Алгоритм DEAL (cipher/deal/deal.go)

Реализация DEAL с использованием DES в качестве раундовой функции через адаптер:
- Размер блока: 16 байт
- Размер ключа: 24 байта
- 6 раундов
- `DESAdapter` адаптирует DES для использования в качестве раундовой функции

```go
deal := deal.NewDEAL()
err := deal.SetKey(ctx, key) // 24 байта
encrypted, err := deal.Encrypt(ctx, plaintext) // 16 байт
```

### 6. Контекст шифрования (cipher/context.go)

Класс `CipherContext` предоставляет высокоуровневый API для шифрования с поддержкой:

#### Режимы шифрования:
- ECB (Electronic Codebook) - с распараллеливанием
- CBC (Cipher Block Chaining)
- PCBC (Propagating CBC)
- CFB (Cipher Feedback)
- OFB (Output Feedback)
- CTR (Counter)
- RandomDelta (пользовательский режим)

#### Режимы набивки:
- Zeros - заполнение нулями
- ANSI X.923 - нули + длина в последнем байте
- PKCS7 - все байты равны длине набивки
- ISO10126 - случайные байты + длина

#### Асинхронные операции:
- `EncryptBytes` / `DecryptBytes` - шифрование массивов байтов
- `EncryptFile` / `DecryptFile` - шифрование файлов
- `EncryptStream` / `DecryptStream` - шифрование потоков

```go
ctx := context.Background()
cipherCtx, err := cipher.NewCipherContext(
    des.NewDES(),
    key,
    cipher.CBC,
    cipher.PKCS7,
    iv,
)

encrypted, err := cipherCtx.EncryptBytes(ctx, plaintext)
decrypted, err := cipherCtx.DecryptBytes(ctx, encrypted)

err = cipherCtx.EncryptFile(ctx, "input.txt", "encrypted.bin")
err = cipherCtx.DecryptFile(ctx, "encrypted.bin", "decrypted.txt")
```

## Примеры использования

### DES с различными режимами

```go
package main

import (
    "context"
    "github.com/masterkusok/crypto/cipher"
    "github.com/masterkusok/crypto/cipher/des"
)

func main() {
    ctx := context.Background()
    key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
    iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    
    cipherCtx, _ := cipher.NewCipherContext(
        des.NewDES(),
        key,
        cipher.CBC,
        cipher.PKCS7,
        iv,
    )
    
    plaintext := []byte("Secret message")
    encrypted, _ := cipherCtx.EncryptBytes(ctx, plaintext)
    decrypted, _ := cipherCtx.DecryptBytes(ctx, encrypted)
}
```

### DEAL шифрование

```go
package main

import (
    "context"
    "github.com/masterkusok/crypto/cipher"
    "github.com/masterkusok/crypto/cipher/deal"
)

func main() {
    ctx := context.Background()
    key := make([]byte, 24) // 24 байта для DEAL
    iv := make([]byte, 16)  // 16 байт для DEAL
    
    cipherCtx, _ := cipher.NewCipherContext(
        deal.NewDEAL(),
        key,
        cipher.CTR,
        cipher.PKCS7,
        iv,
    )
    
    plaintext := []byte("Secret message")
    encrypted, _ := cipherCtx.EncryptBytes(ctx, plaintext)
    decrypted, _ := cipherCtx.DecryptBytes(ctx, encrypted)
}
```

### Шифрование файлов

```go
err := cipherCtx.EncryptFile(ctx, "document.pdf", "document.pdf.enc")
err = cipherCtx.DecryptFile(ctx, "document.pdf.enc", "document_decrypted.pdf")
```

## Запуск примеров

```bash
cd examples
go run main.go
```

## Тестирование

```bash
# Тест DES
cd cipher/des
go test -v

# Тест всех компонентов
go test ./...
```

## Особенности реализации

1. **Обработка ошибок**: Используются константные ошибки из пакета `errors`, паника не используется
2. **Контексты**: Все операции принимают `context.Context` для управления жизненным циклом
3. **Асинхронность**: Операции шифрования/дешифрования выполняются асинхронно через горутины
4. **Распараллеливание**: Режим ECB использует параллельную обработку блоков
5. **Go doc**: Все публичные функции и типы документированы
6. **Минимализм**: Код написан максимально компактно без избыточности

## Архитектурные паттерны

- **Adapter**: `DESAdapter` адаптирует DES для использования в DEAL
- **Strategy**: Различные режимы шифрования и набивки
- **Template Method**: `FeistelNetwork` определяет структуру, конкретные алгоритмы реализуют детали
- **Factory**: Конструкторы `NewDES()`, `NewDEAL()`, `NewCipherContext()`
