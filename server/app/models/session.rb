# A signed-in browser session (Rails 8 authentication scaffold, adapted to
# Person). Session fixation is handled by rotating the session id cookie on
# every sign-in (start_new_session_for) per plan §18.
class Session < ApplicationRecord
  belongs_to :person
end
