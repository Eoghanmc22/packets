package com.github.steveice10.mc.protocol.packet.ingame.client.window;

import com.github.steveice10.packetlib.io.NetInput;
import com.github.steveice10.packetlib.io.NetOutput;
import com.github.steveice10.packetlib.packet.Packet;
import lombok.*;

import java.io.IOException;

@Data
@ToString
@EqualsAndHashCode
@NoArgsConstructor()
public class ClientDisplayedRecipePacket implements Packet {
    private @NonNull String recipeId;

    @Override
    public void read(NetInput in) throws IOException {
        this.recipeId = in.readString();
    }

    @Override
    public void write(NetOutput out) throws IOException {
        out.writeString(this.recipeId);
    }

    @Override
    public boolean isPriority() {
        return false;
    }
}
