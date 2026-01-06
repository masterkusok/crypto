# crypto
Golang library, that implements several cryptographical algorithms.

## Структура проекта

```
crypto/
├── bits/           # Функции для работы с битами и перестановками
├── cipher/         # Криптографические алгоритмы и режимы шифрования
│   ├── des/       # Реализация DES
│   ├── deal/      # Реализация DEAL
│   └── rsa/       # Реализация RSA
├── errors/         # Константные ошибки
├── math/           # Теоретико-числовые функции
└── tables/         # Таблицы перестановок и S-блоки для DES

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

### 6. Теоретико-числовые функции (math/math.go)

Пакет предоставляет базовые функции теории чисел:

```go
// Символ Лежандра (a/p) для простого p
legendre := math.Legendre(2, 7) // 1

// Символ Якоби (a/n) для нечетного n
jacobi := math.Jacobi(5, 9) // 1

// НОД через алгоритм Евклида
gcd := math.GCD(48, 18) // 6

// Расширенный алгоритм Евклида (НОД + соотношение Безу)
gcd, x, y := math.ExtendedGCD(48, 18) // gcd=6, 48*x + 18*y = 6

// Возведение в степень по модулю
result := math.ModPow(2, 10, 1000) // 24
```

#### Вероятностные тесты простоты (math/primality.go)

Реализованы на базе паттерна "Шаблонный метод" с интерфейсом `PrimalityTester`:

```go
// Тест Ферма
fermat := math.NewFermatTest()
isPrime := fermat.IsProbablyPrime(17, 0.99) // true

// Тест Соловея-Штрассена
solovay := math.NewSolovayStrassenTest()
isPrime = solovay.IsProbablyPrime(561, 0.99) // false (число Кармайкла)

// Тест Миллера-Рабина
miller := math.NewMillerRabinTest()
isPrime = miller.IsProbablyPrime(104729, 0.999) // true
```

### 7. Алгоритм RSA (cipher/rsa/rsa.go)

Сервис для шифрования/дешифрования с использованием RSA:
- Вложенный сервис `KeyGenerator` для генерации ключей
- Передача теста простоты через интерфейс `PrimalityTester`
- Защита от атаки Ферма (|p-q| достаточно велико)
- Защита от атаки Винера (d > N^(1/4) / 3)
- Возможность многократной генерации ключей
- Атака Винера для восстановления приватного ключа

```go
// Создание RSA сервиса с тестом Миллера-Рабина
rsa := rsa.NewRSA(math.NewMillerRabinTest(), 0.99, 512)

// Генерация ключевой пары
err := rsa.GenerateKeyPair()

// Шифрование
ciphertext, err := rsa.Encrypt([]byte("Secret message"))

// Дешифрование
plaintext, err := rsa.Decrypt(ciphertext)

// Атака Винера
result := rsa.WienerAttack(publicKey)
if result.Success {
    // result.D - найденная экспонента
    // result.Phi - функция Эйлера
    // result.Convergents - подходящие дроби
}
```

### 8. Контекст шифрования (cipher/context.go)

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
- **Template Method**: `FeistelNetwork` определяет структуру, конкретные алгоритмы реализуют детали; `primalityTest` определяет алгоритм теста простоты, конкретные тесты реализуют одну итерацию через функцию
- **Nested Type**: `KeyGenerator` - вложенный сервис для генерации ключей RSA
