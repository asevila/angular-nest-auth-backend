import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import  * as bcryptjs from "bcryptjs";
import { JwtService } from '@nestjs/jwt';

import { UpdateAuthDto } from './dto/update-auth.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';

import { User } from './entities/user.entity';
import { LoginDto } from './dto/login.dto';

import { JwtPayload } from './interfaces/jwt-paylod';
import { LoginResponse } from './interfaces/login-respose';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name ) 
    private userModel: Model<User>,
    
    private jwtService: JwtService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try {
      
      const { password, ...userData } = createUserDto;
  
      const newUser = new this.userModel({
        // 1- Encriptar la contraseña
        password: bcryptjs.hashSync( password, 10 ),
        // 2- Guardar el usuario
        ...userData
      });

      await newUser.save();
      
      const {password:_, ...user} = newUser.toJSON(); 

      return user;

    } catch (error) {
      if( error.code === 11000){
        throw new BadRequestException(`${ createUserDto.email } already exists!`);
      }
      throw new InternalServerErrorException('Something terrible happend!!!!');
    }

  }

  async register( registerUserDto: RegisterUserDto ): Promise<LoginResponse> {

    const user = await this.create( registerUserDto );

    return {
      user: user,
      token: this.getJWToken( {id: user._id })
    }
  }


  async login( loginDto: LoginDto): Promise<LoginResponse> {

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if ( !user ){
      throw new UnauthorizedException('Not valid credentials - email');
    }
    
    if ( !bcryptjs.compareSync( password, user.password) ){
      throw new UnauthorizedException('Not valid credentials - password');
    }
    /**
     * User {_id, name, email, roles,}
     * Token -> ASD.ASDASDAS.ASDASDASDASD
     */

    const { password:_, ...rest} = user.toJSON();


    return {
      user: rest,
      token: this.getJWToken({ id: user.id }),
    };
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  async findUserById( userId: string ) {
    const user = await this.userModel.findById( userId );
    const { password, ...rest } = user.toJSON();
    return rest;

  }

  checkToken() {

  }


  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWToken( paylod: JwtPayload ) {
    const token = this.jwtService.sign(paylod);
    return token;
  }
}
