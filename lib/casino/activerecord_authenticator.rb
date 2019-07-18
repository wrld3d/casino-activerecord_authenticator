require 'active_record'
require 'unix_crypt'
require 'bcrypt'
require 'phpass'
require 'digest'

class CASino::ActiveRecordAuthenticator

  class AuthDatabase < ::ActiveRecord::Base
    self.abstract_class = true
  end

  # @param [Hash] options
  def initialize(options)
    if !options.respond_to?(:deep_symbolize_keys)
      raise ArgumentError, "When assigning attributes, you must pass a hash as an argument."
    end
    @options = options.deep_symbolize_keys
    raise ArgumentError, "Table name is missing" unless @options[:table]
    if @options[:model_name]
      model_name = @options[:model_name]
    else
      model_name = @options[:table]
      if @options[:connection].kind_of?(Hash) && @options[:connection][:database]
        model_name = "#{@options[:connection][:database].gsub(/[^a-zA-Z]+/, '')}_#{model_name}"
      end
      model_name = model_name.classify
    end
    model_class_name = "#{self.class.to_s}::#{model_name}"
    eval <<-END
      class #{model_class_name} < AuthDatabase
        self.table_name = "#{@options[:table]}"
        self.inheritance_column = :_type_disabled
      end
    END

    @model = model_class_name.constantize
    @model.establish_connection @options[:connection]
  end

  def validate(username, password)
    user = @model.send("find_by_#{@options[:username_column]}!", username)
    password_from_database = user.send(@options[:password_column])

    if valid_password?(password, password_from_database)
      user_data(user)
    else
      false
    end

  rescue ActiveRecord::RecordNotFound
    false
  end

  def load_user_data(username)
    user = @model.send("find_by_#{@options[:username_column]}!", username)
    user_data(user)
  rescue ActiveRecord::RecordNotFound
    nil
  end

  private
  def user_data(user)
    { username: user.send(@options[:username_column]), extra_attributes: extra_attributes(user) }
  end

  def valid_password?(password, password_from_database)
    return false if password_from_database.blank?
    
    if valid_password_with_md5?(password, password_from_database)
      true
    elsif ENV['PASSWORD_SALT'] != nil && valid_password_with_salted_md5?(password, password_from_database, ENV['PASSWORD_SALT'])
      true
    elsif valid_password_with_bcrypt?(password, password_from_database)
      true
    elsif valid_password_with_unix_crypt?(password, password_from_database)
      true
    elsif valid_password_with_phpass?(password, password_from_database)
      true
    else
      false
    end
  end

  def valid_password_with_md5?(password, password_from_database)
    Digest::MD5.hexdigest(password) == password_from_database
  end

  def valid_password_with_salted_md5?(password, password_from_database, salt)
    Digest::MD5.hexdigest("#{salt}#{password}") == password_from_database
  end

  def valid_password_with_bcrypt?(password, password_from_database)
    password_with_pepper = password + @options[:pepper].to_s
    BCrypt::Password.new(password_from_database) == password_with_pepper
  end

  def valid_password_with_unix_crypt?(password, password_from_database)
    UnixCrypt.valid?(password, password_from_database)
  end

  def valid_password_with_phpass?(password, password_from_database)
    Phpass.new().check(password, password_from_database)
  end

  def extra_attributes(user)
    attributes = {}
    extra_attributes_option.each do |attribute_name, database_column|
      attributes[attribute_name] = user.send(database_column)
    end
    attributes
  end

  def extra_attributes_option
    @options[:extra_attributes] || {}
  end
end
