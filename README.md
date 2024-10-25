# OAuth2CLI-swift

This is the swift translation of [mutt_oauth2.py](https://gitlab.com/muttmua/mutt/-/blob/master/contrib/mutt_oauth2.py), but stores the tokens in Apple Keychain instead of a file.

For detailed usage, see the help of the command.

This is intended just for personal use only. However, pull requests are welcome.

Because I wrote it just for my self and I do not use GMail, so this program does not support GMail. 

Also, when it prompts you for the code from the browser, you need to split the code into two parts and input them separately. This is due to a weird bug that the `readLine()` function hangs if you feed it a string that is too long.