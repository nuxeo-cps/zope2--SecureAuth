# (C) Copyright 2002, 2003 Nuxeo SARL <http://nuxeo.com>
# Authors: Thierry Delprat <td@nuxeo.com>
#          Olivier Grisel <og@nuxeo.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$
"""SecureAuth is version of CookieCrumbler that is that allows certificate
based authentication thanks to Apache
"""

import SecureAuth

product_name = 'SecureAuth'

def initialize(registrar):
    registrar.registerClass(SecureAuth.SecureAuth,
                      constructors=(SecureAuth.manage_addSAForm,
                                    SecureAuth.manage_addSA,))
