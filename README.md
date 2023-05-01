<h1 align="center"> WinHandKill </h1>

A plugin for x64dbg that allows you to hook the **Local Security Authority Subsystem Service** process to extract all possible TLS(On handshake, Import, Export or Generate) keys from the operating system using the SeDebugPrivilege escalation to make malware analysis faster and easier.

![A Kurumi tokisaki prompt: "anime "Date A Live". You have long, straight black hair that reaches down to your waist, with side-swept bangs that cover one of your red eyes. Its eyes are large and expressive, with a bright red iris. His skin is pale and contrasts with the red of his eyes. You wear a black school uniform with red trim, over-the-knee socks and black boots. In addition, you have a generally mysterious and endearing appearance, which can attract the attention of those around you.", generated on https://huggingface.co/spaces/PaddlePaddle/ERNIE-ViLG](/images/mascote.png "AI GENERATED MASCOT")

## How to use

It is extremely important that before using it, you read the article I am going to suggest here. It will explain everything from how the plugin works to how to use it with detailed steps, and even applied to a real malware sample. I will also provide the exact version of the operating system and everything you need to apply it to your own VM.

There are two versions available for reading, the first one, obviously, in a language that everyone can understand, English:

[Click here to read and understand the project.](https://joaovitor.gq/posts/Malware-Analysis-Writeup-Bat-Stealer(Chine-Encode)-and-introduzing-WinHandKill-X64DBG-Plugin-English/)

For portuguese: Se você fala português, você não necessariamente precisa falar inglês para usar, você poder ler no seu idioma nativo:

[Clique aqui para ler e entender o projeto](https://joaovitor.gq/posts/Malware-Analysis-Writeup-Bat-Stealer(Chine-Encode)-and-introduzing-WinHandKill-X64DBG-Plugin-Portugues/)

#### How to use video

A video will be recorded soon (you can collaborate by recording one in your native language).

## How build

You need to use the Visual Studio console. I recommend Visual Studio 2022, and of course, you need to have CMake installed from the Visual Studio Installer.

With everything ready, you just need to open the Visual Studio console and type the following commands in the project root directory:

```
cmake -B build64 -A x64
cmake --build build64 --config Release
```

After that, you need to open the generated Visual Studio project and compile it.

## How colaborate

I need to expand the project, can you help me by attaching your "ncrypt.dll" and the version of your operating system to an issue Or you could even collaborate with code (for that, open an issue so we can discuss and grant you permission on a branch).