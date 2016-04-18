import random

banner1 = """\n
           ---_ ...... _/_ -
          /  .      ./ .'*\\
          :''         /_|-'  \.
         /                     )
       _/                  >   '
     /   .   .       _.-" /  .'
     \           __/"     /.'
       \ '--  .-" /     / /'
        \|  \ | /     / /
             \:     / /
          `\/     / /
           \__`\/ /
               \_|

|_PytheM - Python man in the middle tool
\n"""



def get_banner():
	banners = [banner1]
	return random.choice(banners)
