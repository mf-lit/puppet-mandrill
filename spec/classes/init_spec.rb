require 'spec_helper'
describe 'mandrill' do

  context 'with defaults for all parameters' do
    it { should contain_class('mandrill') }
  end
end
