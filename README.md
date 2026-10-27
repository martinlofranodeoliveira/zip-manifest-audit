# zip-manifest-audit

Offline ZIP central-directory inventory and metadata audit, using only the
Python standard library. Requires Python 3.10 or later.

[English](#english) · [Português](#português)

## English

`zip-manifest-audit` reports names, sizes, flags and potential concerns from a
ZIP's central directory. It never extracts files, opens or reads member
contents, checks member CRCs, or calls `testzip`. It makes no antivirus or safety
certification claim. A clean report does not establish that an archive is safe.

### Run

From the project directory, without installing dependencies:

```sh
python -m zip_manifest_audit archive.zip
python -m zip_manifest_audit archive.zip --format markdown
python -m zip_manifest_audit archive.zip --max-ratio 500 --fail-on-findings
```

Use `python3` in these commands if that is your Python 3 executable.

JSON is the default output format. `--max-ratio` defaults to `1000` and accepts
integers from `1` through `1000000`. `--help` displays the CLI help.

| Exit status | Meaning |
| --- | --- |
| `0` | Valid audit, including an audit with findings; also `--help`. |
| `1` | Findings exist and `--fail-on-findings` was supplied. |
| `2` | Invalid input or arguments. A generic diagnostic goes to stderr; no partial report is emitted to stdout. |

The utility reads its input only and writes its report to stdout. It does not
modify the source, create report files, use temporary extraction, launch
subprocesses, or access the network. Shell redirection can explicitly save a
report if desired.

### Python API

```python
from zip_manifest_audit import ArchiveError, audit_zip

try:
    report = audit_zip("archive.zip", max_ratio=1000)
except ArchiveError:
    print("The archive could not be audited.")
else:
    print(report["sha256"])
    print(report["summary"])
    for finding in report["findings"]:
        print(finding["code"], finding["index"], repr(finding["path"]))
```

`audit_zip(path, *, max_ratio=1000) -> dict` accepts an explicit regular source
file of at most **16 MiB (16,777,216 bytes)**. It captures the source bytes once
and hashes those exact snapshot bytes with SHA-256. ZIP and ZIP64 directory
metadata are parsed by `zipfile`. At most **10,000 entries** are accepted:
the standard library constructs its directory metadata before this count is
checked, so this is not a bound on that initial parsing work. `max_ratio` must
be a strict integer in the range above; booleans are invalid.

`ArchiveError` subclasses `ValueError`. Invalid containers, invalid metadata
and source I/O failures produce generic errors without source paths or archive
contents in the message.

The result contains four keys:

| Key | Contents |
| --- | --- |
| `sha256` | Lowercase SHA-256 digest of the exact source snapshot. |
| `entries` | List in central-directory order, including directories. |
| `summary` | `files`, `directories`, `total_uncompressed_bytes`, `total_compressed_bytes`. |
| `findings` | List of objects with `code`, zero-based entry `index`, and original member `path`. |

Each entry contains `index`, `name`, `is_dir`, `compressed_size`,
`uncompressed_size`, `crc32` (eight lowercase hexadecimal digits), `compression`
(numeric method), `encrypted` and `is_symlink`. Names use the decoded original
member name, including a NUL character before any `ZipInfo.filename`
truncation. A directory is identified by an original name ending in `/`;
symlinks use Unix file-type metadata in external attributes. Member names are
data and are never used as local paths. The summary excludes directories from
`files` and sums sizes across **all** entries, including directories.

### Findings

Findings follow entry order and the code order in this table. A single entry
can have multiple findings.

| Code | Directory metadata rule |
| --- | --- |
| `absolute_path` | Name starts with `/` or `\`, or with an ASCII drive letter followed by `:`. |
| `parent_segment` | A literal `..` segment occurs when splitting on `/` or `\`. |
| `backslash_path` | Name contains `\`. |
| `control_character` | Name contains ASCII 0–31 or DEL (127). |
| `duplicate_name` | An earlier entry has the exact original name. |
| `case_collision` | An earlier, differently named entry has the same key after replacing `\` with `/` and applying `casefold()`. |
| `symlink` | Unix external attributes describe a symbolic link. |
| `encrypted` | General-purpose flag bit 0 is set. |
| `high_ratio` | Claimed uncompressed size is positive and compressed size is zero, or uncompressed size exceeds `max_ratio × compressed_size`. |
| `other_compression` | Compression method is neither stored (`0`) nor deflate (`8`). |

Duplicates and case collisions are reported only on later entries. A finding
is an observation about metadata, not proof of an exploit or of rejection by
any extractor. Sizes, CRCs, compression identifiers and flags are untrusted
central-directory claims, not observations of member payloads. There is no CRC
or payload-integrity verification, payload inspection, full ZIP format
validation, decompression-bomb prevention, complete Windows/POSIX path
normalization, or Unicode spoof detection.

JSON uses ASCII escaping. Markdown escapes identifiers to avoid active HTML,
table delimiters, newlines, inline links, bare URLs and email links. These
formats are **not a secrets scrubber**: source names, member names, paths and
other report data can still be sensitive. Review reports before sharing them.

### Synthetic example

```sh
python examples/create_synthetic_zip.py synthetic.zip
python -m zip_manifest_audit synthetic.zip --format markdown
```

The creator writes a new, small ZIP with synthetic parent and absolute names,
backslashes, case variants, duplicate names, Unix symlink metadata and highly
compressible data. It refuses to overwrite an existing file. The audit reads
only directory metadata; it does not follow the example symlink or materialize
any of these member names on disk. The creator itself writes synthetic member
data to construct the fixture.

Licensed under the [MIT License](LICENSE), copyright MartinLofrano.

## Português

`zip-manifest-audit` faz um inventário local do diretório central de um ZIP e
aponta possíveis problemas nos metadados. Usa apenas a biblioteca padrão do
Python 3.10 ou posterior. Nunca extrai arquivos, abre ou lê o conteúdo dos
membros, verifica seus CRCs ou chama `testzip`. Não é antivírus e não certifica
a segurança de um arquivo. A ausência de alertas não comprova segurança.

### Executar

Na pasta do projeto, sem instalar dependências:

```sh
python -m zip_manifest_audit arquivo.zip
python -m zip_manifest_audit arquivo.zip --format markdown
python -m zip_manifest_audit arquivo.zip --max-ratio 500 --fail-on-findings
```

Use `python3` nos comandos se esse for o executável do seu Python 3.

O formato padrão é JSON. `--max-ratio` tem valor padrão `1000` e aceita inteiros
de `1` a `1000000`. `--help` exibe a ajuda.

| Código de saída | Significado |
| --- | --- |
| `0` | Auditoria válida, inclusive quando há alertas; também usado por `--help`. |
| `1` | Há alertas e a opção `--fail-on-findings` foi usada. |
| `2` | Entrada ou argumentos inválidos. Uma mensagem genérica vai para stderr e nenhum relatório parcial vai para stdout. |

A ferramenta somente lê a entrada e envia o relatório para stdout. Não altera
o arquivo de origem, cria arquivos de relatório, extrai conteúdo temporário,
inicia subprocessos ou acessa a rede. O redirecionamento do shell pode salvar
um relatório quando solicitado explicitamente.

### API Python

```python
from zip_manifest_audit import ArchiveError, audit_zip

try:
    relatorio = audit_zip("arquivo.zip", max_ratio=1000)
except ArchiveError:
    print("Não foi possível auditar o arquivo.")
else:
    print(relatorio["sha256"])
    print(relatorio["summary"])
    for alerta in relatorio["findings"]:
        print(alerta["code"], alerta["index"], repr(alerta["path"]))
```

`audit_zip(path, *, max_ratio=1000) -> dict` recebe um caminho explícito para
um arquivo regular de até **16 MiB (16.777.216 bytes)**. Os bytes da origem são
capturados uma única vez e o SHA-256 corresponde exatamente a essa captura.
`zipfile` interpreta os metadados ZIP e ZIP64. São aceitas até **10.000
entradas**. A biblioteca padrão constrói os metadados do diretório antes da
verificação dessa quantidade; portanto, o limite não restringe o trabalho
inicial dessa interpretação. `max_ratio` deve ser estritamente inteiro no
intervalo indicado; valores booleanos são inválidos.

`ArchiveError` herda de `ValueError`. Contêineres ou metadados inválidos e
falhas de entrada/saída geram erros genéricos, sem caminhos da origem ou
conteúdo do arquivo na mensagem.

O resultado tem quatro chaves:

| Chave | Conteúdo |
| --- | --- |
| `sha256` | SHA-256 em hexadecimal minúsculo dos bytes exatos capturados da origem. |
| `entries` | Lista na ordem do diretório central, incluindo diretórios. |
| `summary` | `files`, `directories`, `total_uncompressed_bytes`, `total_compressed_bytes`. |
| `findings` | Objetos com `code`, `index` da entrada começando em zero e `path` original do membro. |

Cada entrada contém `index`, `name`, `is_dir`, `compressed_size`,
`uncompressed_size`, `crc32` (oito dígitos hexadecimais minúsculos),
`compression` (método numérico), `encrypted` e `is_symlink`. O nome é o nome
original decodificado, incluindo eventual NUL anterior ao truncamento de
`ZipInfo.filename`. Um diretório é identificado pelo nome original terminado
em `/`; links simbólicos são identificados pelo tipo de arquivo Unix nos
atributos externos. Os nomes são dados e nunca são usados como caminhos
locais. `files` exclui diretórios e as somas de tamanhos incluem **todas** as
entradas, inclusive diretórios.

### Alertas

Os alertas seguem a ordem das entradas e a ordem dos códigos na tabela. Uma
entrada pode ter vários alertas.

| Código | Regra sobre os metadados do diretório |
| --- | --- |
| `absolute_path` | Nome começa com `/` ou `\`, ou com letra ASCII de unidade seguida de `:`. |
| `parent_segment` | Há um segmento literal `..` ao separar por `/` ou `\`. |
| `backslash_path` | Nome contém `\`. |
| `control_character` | Nome contém ASCII de 0 a 31 ou DEL (127). |
| `duplicate_name` | Uma entrada anterior tem o mesmo nome original exato. |
| `case_collision` | Uma entrada anterior com nome diferente tem a mesma chave após trocar `\` por `/` e aplicar `casefold()`. |
| `symlink` | Os atributos externos Unix indicam um link simbólico. |
| `encrypted` | O bit 0 das flags de uso geral está ativo. |
| `high_ratio` | O tamanho descompactado declarado é positivo e o compactado é zero, ou o descompactado supera `max_ratio × tamanho compactado`. |
| `other_compression` | Método de compactação diferente de armazenado (`0`) e deflate (`8`). |

Duplicatas e colisões são apontadas somente nas entradas posteriores. Um
alerta descreve metadados: não comprova exploração nem rejeição por algum
extrator. Tamanhos, CRCs, métodos e flags são declarações não confiáveis do
diretório, e não dados observados no conteúdo. Não há verificação de CRC ou
integridade do conteúdo, inspeção dos membros, validação completa do formato
ZIP, prevenção de bombas de descompactação, normalização completa de caminhos
Windows/POSIX ou detecção de falsificação visual Unicode.

O JSON usa escapes ASCII. O Markdown escapa identificadores para impedir HTML
ativo, delimitadores de tabela, quebras de linha, links embutidos, URLs avulsas
e links de e-mail. Esses formatos **não removem segredos**: nomes da origem,
nomes dos membros, caminhos e outros dados do relatório ainda podem ser
sensíveis. Revise o relatório antes de compartilhá-lo.

### Exemplo sintético

```sh
python examples/create_synthetic_zip.py synthetic.zip
python -m zip_manifest_audit synthetic.zip --format markdown
```

O criador grava um ZIP pequeno e novo com nomes sintéticos relativos ao pai e
absolutos, barras invertidas, variantes de maiúsculas/minúsculas, nomes
duplicados, metadados Unix de link simbólico e dados altamente compactáveis.
Ele se recusa a sobrescrever um arquivo existente. A auditoria lê somente os
metadados do diretório: não segue o link nem cria os caminhos dos membros no
disco. O criador grava conteúdo sintético para montar o exemplo.

Licenciado sob a [licença MIT](LICENSE), copyright MartinLofrano.
