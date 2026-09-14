# frozen_string_literal: true

# Option-1 reservation carries a disk-encryption POLICY proof, not the secret
# (docs/p0/installer-enrollment.md): the installer records "planned" at STEP 0;
# the server never sees the LUKS passphrase itself (§10/§242/§397).
class AddDiskEncryptionToEnrollmentRequests < ActiveRecord::Migration[8.1]
  def change
    add_column :enrollment_requests, :disk_encryption, :string
  end
end
