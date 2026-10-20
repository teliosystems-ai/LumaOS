"""Final-alias source/policy regression, not loaded AppArmor qualification."""
from pathlib import Path
import re
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
PROFILES=ROOT/'image/overlay/etc/apparmor.d'


class MediaIdentityPolicy(unittest.TestCase):
    def parts(self):
        speech=(PROFILES/'luma-workspace-speech').read_text()
        capture=(PROFILES/'luma-workspace-capture').read_text()
        return [speech.split('profile luma-workspace-speech-play ',1)[1],
            capture.split('profile luma-workspace-capture-audio ',1)[1].split('profile luma-workspace-capture-video ',1)[0],
            capture.split('profile luma-workspace-capture-video ',1)[1]]

    def test_actual_final_alias_shapes_resolve_only_to_three_exact_public_read_targets(self):
        assemble=(ROOT/'image/assemble.py').read_text()
        self.assertIn("source.symlink_to('../var/lib/luma-os/identity/'+name)",assemble)
        self.assertIn("(ROOT/'etc/machine-id').symlink_to('../var/lib/luma-os/identity/machine-id')",assemble)
        self.assertIn("(ROOT/'var/lib/dbus/machine-id').symlink_to('../luma-os/identity/machine-id')",assemble)
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);identity=root/'var/lib/luma-os/identity';identity.mkdir(parents=True)
            (root/'etc').mkdir();(root/'var/lib/dbus').mkdir()
            for public in ('passwd','group','machine-id'):
                (identity/public).write_bytes(b'public fixture, not host identity\n')
                (root/'etc'/public).symlink_to('../var/lib/luma-os/identity/'+public)
                self.assertEqual((root/'etc'/public).resolve(strict=True),identity/public)
            (root/'var/lib/dbus/machine-id').symlink_to('../luma-os/identity/machine-id')
            self.assertEqual((root/'var/lib/dbus/machine-id').resolve(strict=True),identity/'machine-id')
            for part in self.parts():
                self.assertIn('/var/lib/luma-os/identity/{passwd,group,machine-id} r,',part)
                for directory in ('/var/','/var/lib/','/var/lib/luma-os/','/var/lib/luma-os/identity/'):
                    self.assertIn(directory+' r,',part)

    def test_no_blanket_read_conflict_writes_maps_and_all_private_authorities_stay_denied(self):
        for part in self.parts():
            self.assertNotIn('deny /var/lib/luma-os/** rwklmx,',part)
            self.assertIn('deny /var/lib/luma-os/** wklmx,',part)
            self.assertIn('deny /var/lib/luma-os/identity/{shadow,gshadow} rwklmx,',part)
            self.assertIn('deny /var/lib/luma-broker{,/**} rwklmx,',part)
            self.assertIn('deny /var/lib/luma-os/{admin,principals,resource-checkpoint,content-custody,content-store,models,model-packs,model-qualifications}{,/**} rwklmx,',part)
            product_allows=re.findall(r'^\s*(/var/lib/luma-os/[^\s]*)\s+([a-z]+),$',part,re.M)
            self.assertEqual(product_allows,[('/var/lib/luma-os/','r'),('/var/lib/luma-os/identity/','r'),
                ('/var/lib/luma-os/identity/{passwd,group,machine-id}','r')])
            self.assertNotIn('capability ',part)
            for denial in ('deny network inet,','deny network inet6,','deny dbus,','deny /etc/{shadow,gshadow} rwklmx,'):
                self.assertIn(denial,part)
        render=(PROFILES/'luma-workspace-speech').read_text().split('profile luma-workspace-speech-play ',1)[0]
        self.assertIn('deny /var/lib/luma-os/** rwklmx,',render)
        self.assertNotIn('/var/lib/luma-os/identity/{passwd,group,machine-id} r,',render)


if __name__=='__main__':unittest.main()
