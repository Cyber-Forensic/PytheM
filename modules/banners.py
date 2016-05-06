#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016 m4n3dw0lf
#
# Este arquivo é parte do programa PytheM

# PytheM é um software livre; você pode redistribuí-lo e/ou 
# modificá-lo dentro dos termos da Licença Pública Geral GNU como 
# publicada pela Fundação do Software Livre (FSF); na versão 3 da 
# Licença, ou (na sua opinião) qualquer versão.

# Este programa é distribuído na esperança de que possa ser  útil, 
# mas SEM NENHUMA GARANTIA; sem uma garantia implícita de ADEQUAÇÃO
# a qualquer MERCADO ou APLICAÇÃO EM PARTICULAR. Veja a
# Licença Pública Geral GNU para maiores detalhes.

# Você deve ter recebido uma cópia da Licença Pública Geral GNU junto
# com este programa, Se não, veja <http://www.gnu.org/licenses/>.


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

|_PytheM - Python man in the middle/pentesting tool
\n"""



def get_banner():
	banners = [banner1]
	return random.choice(banners)
