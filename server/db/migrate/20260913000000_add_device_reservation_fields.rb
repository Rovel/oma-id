# frozen_string_literal: true

# Option-1 reserve-then-activate (docs/p0/installer-enrollment.md, plan §6.3/
# §7.2 step 5): acceptance creates the device as a RESERVATION (state
# pending); the first signed check-in (proof the installed machine holds the
# staged key) activates it and delivers the one-time first-login bootstrap
# credential. The bootstrap is single-use: nulled on delivery so nothing
# persists server-side past first contact.
class AddDeviceReservationFields < ActiveRecord::Migration[8.1]
  def change
    change_table :devices do |t|
      # style: nullability mirrors the existing columns; values are set at
      # enrollment acceptance and nulled/delivered on first check-in.
      t.string :bootstrap_credential
      t.datetime :bootstrap_delivered_at
      t.datetime :first_boot_acknowledged_at
    end
  end
end
