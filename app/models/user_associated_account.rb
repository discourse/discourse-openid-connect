class UserAssociatedAccount < ActiveRecord::Base
  belongs_to :user
end
