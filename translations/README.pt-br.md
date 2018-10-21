# Introdução
Essa ferramenta traduz (ou constrói) estaticamente (AOT) binários para LLVM IR.

# Começando (Linux/Mac)
## Construindo como parte da árvore LLVM

1.  `mkdir $PWD/src && mkdir -p $PWD/build/llvm && cd src`
2.  `git clone https://github.com/llvm-mirror/llvm && pushd llvm && git checkout master && popd`
3.  `pushd llvm/tools && git clone https://github.com/llvm-mirror/clang && git checkout master && popd`
4.  `pushd llvm/tools && git clone https://github.com/Microsoft/llvm-mctoll && git checkout master && popd`
7.  `cd ../build/llvm`
7.  Execute o comando cmake que você costuma usar para compilar llvm
8.  Execute `make llvm-mctoll` ou `ninja llvm-mctoll`

## Uso

Gerar o LLVM IR para um binário:

`llvm-mctoll -d <binary>`

O resultado obtido é gerado como `<binary>-dis.ll`.

Para verificar a exatidão do `<binary>-dis.ll`
1. compile `<binary>-dis.ll` para um executável (ou para uma biblioteca compartilhada se `<binary>` for uma biblioteca compartilhada) usando `clang`.
2. Execute o  resultante do executável ( ou use o resultante da biblioteca compartilhada `<binary>-dis` no lugar de `<binary>`) para verificar se o compartamento da execução está idêntico ao do `<binary>` original.

Testes no repositório da ferramenta são escritos seguindo a metodologia descrita acima.

Para impimir a saída de depuração:

`llvm-mctoll -d -print-after-all <binary>`

## Compile e teste

Execute os testes pelo comando `make check-mctoll` ou `ninja check-mctoll`

Atualmente, o desenvolvimento e os teste estão sendo realizados no Ubuntu 18.04. Espera-se que a compilação e o teste funcionem no Ubuntu 16.04, 17.04 and 17.10.

# Situação atual

A ferramenta é capaz de criar bibliotecas compartilhadas e executáveis Linux x86_64 e Arm32 com chamadas de função que tem argumentos variados (como printf) para LLVM IR.

O suporte para o código gerado para a instrução `switch` precisa ser adicionado.

Criação de binários C++ precisam ser adicionados. 

# Contribuindo

Esse projeto recebe contribuições e sugestões. A maioria das contribuições precisa que você aceite um Contrato de Licença de Contribuinte (CLA) declarando que você tem o direito e que realmente nos concede os direitos de usar sua contribuição. Para detalhes, visite: https://cla.microsoft.com.

Quando você submeter um pull requesta, um CLA-bot vai determinar automaticamente se você precisa fornecer um CLA e decora apropriadamente o PR (por exemplo, comentário, label). Simplismente siga as instruções providenciadas pelo bot. Você só vai precisar fazer isso uma vez em todos os repositórios usando nosso CLA.

Este projeto adotou o Código de Conduta Open Source da Microsoft. Para obter mais informações, consulte as perguntas frequentes (FAQs) sobre o código de conduta ou entre em contato com opencode@microsoft.com com perguntas ou comentários adicionais.
