
shar $(git ls-files) > memorymodulepp.shar.txt

exit

LLM take context as input

often limited to text
or binaries which it can convert to text (OCR pdf or parse docx)

by attaching files
or uploading one big file

A shar is a good way to

1. upload a git repo
or any set of files
into LLM context

prompt
add the files in this shar archive as artifacts and give the number of files added, do  not show any artifacts to me

2. and receive all artifacts in result

prompt
provide all artifacts as a downloadable shar archive

unshar -c memorymodulepp.shar.txt

Strangely, LLM is very stupid about adding hash codes to ensure integrity don't even try!
