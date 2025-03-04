# Copyright 2016 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.

from kamaki.clients.astakos import AstakosClient
from kamaki.clients.cyclades import CycladesComputeClient

AUTHENTICATION_URL = "https://astakos.example.com/identity/v2.0"
TOKEN = "User-Token"
astakos = AstakosClient(AUTHENTICATION_URL, TOKEN)

service_type = CycladesComputeClient.service_type
endpoint = astakos.get_endpoint_url(service_type)
compute = CycladesComputeClient(endpoint, TOKEN)

#  Find flavor with 2 cores, 20GB disk and 2048MB of ram
pick_flavor = lambda flavor: all(
    flavor["vcpus"] == 2, flavor["disk"] == 20, flavor["ram"] == 2048
)
all_flavors = compute.list_flavors(detail=True)
flavors = list(filter(pick_flavor, all_flavors))

#  Find images with debian in their name
pick_image = lambda image: "debian" in image["name"].lower()
all_images = compute.list_images(detail=True)
images = list(filter(pick_image, all_images))

#  Show results
flavor_ids = "\n\t".join([f["id"] for f in flavors])
print("{num} flavors match\n\t{ids}".format(num=len(flavors), ids=flavor_ids))
image_ids = "\n\t".join([i["id"] for i in images])
print("{num} images match: {ids}".format(num=len(images), ids=image_ids))
