import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

@Schema()
export class User {

    _id?: string;
    
    @Prop({ unique: true, require: true })
    email: string;

    @Prop({ required: true })
    name: string;

    @Prop({ minlength: 6, required: true})
    password?: string;

    @Prop({ default: true })
    isAvtive: boolean;

    @Prop({ type: [String], default: ['user'] })
    roles: string[];

}


export const UserSchema = SchemaFactory.createForClass( User );
